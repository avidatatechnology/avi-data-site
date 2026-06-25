// Avi Data Technology — stripe-webhook
// ------------------------------------------------------------------
// Stripe calls this when a payment changes state. Its only job:
// when an ACH (or any) payment SUCCEEDS, flip the matching invoice to
// "paid" — which makes the client's in-portal receipt available.
// Receipts live in the portal (your design); Stripe never emails one.
//
// Security: Stripe signs every request. We verify the signature with
// the webhook signing secret using Node's built-in crypto — so only
// genuine Stripe calls are honored. No npm dependencies (Node 18+).
//
// Env vars needed (Netlify): STRIPE_WEBHOOK_SECRET (whsec_...),
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY.
// ------------------------------------------------------------------

const crypto = require("crypto");

const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const SUPABASE_URL   = process.env.SUPABASE_URL;
const SERVICE_ROLE   = process.env.SUPABASE_SERVICE_ROLE_KEY;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM     = process.env.EMAIL_FROM || "Avi Data Technology <hello@avidatatechnology.com>";
const PORTAL_URL     = process.env.PORTAL_URL || "https://avidatatechnology.com/portal/";

// Look up the invoice's client email + a couple display fields.
async function invoiceContact(invoiceId) {
  try {
    const ir = await fetch(`${SUPABASE_URL}/rest/v1/invoices?id=eq.${encodeURIComponent(invoiceId)}&select=number,amount_cents,client_id`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } });
    const inv = (await ir.json())[0]; if (!inv) return null;
    const pr = await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(inv.client_id)}&select=email,company_name`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } });
    const prof = (await pr.json())[0] || {};
    const email = (prof.email && !/@clients\.avidatatechnology\.com$/i.test(prof.email)) ? prof.email : null;
    return { email, company: prof.company_name || "there", number: inv.number, amount_cents: inv.amount_cents };
  } catch (e) { return null; }
}
async function sendEmail(to, subject, inner) {
  if (!RESEND_API_KEY || !to) return;
  const html = `<div style="background:#0A0E1A;padding:32px 0;font-family:-apple-system,Inter,Arial,sans-serif"><div style="max-width:480px;margin:0 auto;background:#111726;border:1px solid #1F2A44;border-radius:16px;padding:32px;color:#EAF0FB"><div style="font-weight:800;font-size:18px;margin-bottom:20px">Avi Data <span style="color:#8793AE;font-weight:600">Technology</span></div><h1 style="font-size:20px;margin:0 0 14px">${subject}</h1><div style="color:#C7D0E4;font-size:14px;line-height:1.6">${inner}</div><a href="${PORTAL_URL}" style="display:inline-block;margin-top:24px;background:#6E8BFF;color:#fff;text-decoration:none;padding:12px 22px;border-radius:10px;font-weight:700;font-size:14px">Open your portal</a><div style="margin-top:26px;color:#566179;font-size:12px">hello@avidatatechnology.com</div></div></div>`;
  try { await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify({ from: EMAIL_FROM, to, subject, html }) }); } catch (e) {}
}
function money(c){ return "$" + ((c||0)/100).toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2}); }

// Verify Stripe's signature header against the RAW body.
function verifyStripe(rawBody, sigHeader, secret) {
  if (!sigHeader || !secret) return false;
  let t = null; const v1 = [];
  for (const part of sigHeader.split(",")) {
    const [k, v] = part.trim().split("=");
    if (k === "t") t = v;
    if (k === "v1") v1.push(v);
  }
  if (!t || !v1.length) return false;
  // Reject anything older than 5 minutes (replay protection).
  if (Math.abs(Math.floor(Date.now() / 1000) - Number(t)) > 300) return false;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(`${t}.${rawBody}`, "utf8")
    .digest("hex");
  return v1.some((sig) => {
    try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig)); }
    catch (e) { return false; }
  });
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method not allowed" };
  if (!WEBHOOK_SECRET || !SUPABASE_URL || !SERVICE_ROLE) {
    return { statusCode: 500, body: "Server not configured." };
  }

  const sig = event.headers["stripe-signature"] || event.headers["Stripe-Signature"];
  const raw = event.isBase64Encoded
    ? Buffer.from(event.body || "", "base64").toString("utf8")
    : (event.body || "");

  if (!verifyStripe(raw, sig, WEBHOOK_SECRET)) {
    return { statusCode: 400, body: "Invalid signature" };
  }

  let evt;
  try { evt = JSON.parse(raw); } catch (e) { return { statusCode: 400, body: "Bad payload" }; }

  const obj = evt.data && evt.data.object;
  const invoiceId = obj && obj.metadata && obj.metadata.invoice_id;

  // ACH submitted and clearing -> mark the invoice "processing" (Pending).
  // This is the robust backstop: it fires even if the client closes the tab.
  if (evt.type === "payment_intent.processing" && invoiceId) {
    try {
      await fetch(
        `${SUPABASE_URL}/rest/v1/invoices?id=eq.${encodeURIComponent(invoiceId)}&status=eq.open`,
        {
          method: "PATCH",
          headers: {
            apikey: SERVICE_ROLE,
            Authorization: `Bearer ${SERVICE_ROLE}`,
            "Content-Type": "application/json",
            Prefer: "return=minimal",
          },
          body: JSON.stringify({ status: "processing" }),
        }
      );
    } catch (e) { /* ignore */ }
  }

  // payment succeeded -> mark paid (from open/processing/failed) and email.
  if (evt.type === "payment_intent.succeeded" && invoiceId) {
    try {
      await fetch(
        `${SUPABASE_URL}/rest/v1/invoices?id=eq.${encodeURIComponent(invoiceId)}&status=in.(open,processing,failed)`,
        {
          method: "PATCH",
          headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}`, "Content-Type": "application/json", Prefer: "return=minimal" },
          body: JSON.stringify({ status: "paid", paid_at: new Date().toISOString() }),
        }
      );
      const c = await invoiceContact(invoiceId);
      if (c && c.email) await sendEmail(c.email, "Payment received — thank you",
        `Hi ${c.company},<br><br>Your payment of <b>${money(c.amount_cents)}</b> (invoice ${c.number}) has cleared. A receipt is now available in your portal under Payment history.`);
    } catch (e) {}
  }

  // ACH failed/returned -> mark "failed" so it's flagged for retry, and email.
  if (evt.type === "payment_intent.payment_failed" && invoiceId) {
    try {
      await fetch(
        `${SUPABASE_URL}/rest/v1/invoices?id=eq.${encodeURIComponent(invoiceId)}&status=in.(open,processing)`,
        {
          method: "PATCH",
          headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}`, "Content-Type": "application/json", Prefer: "return=minimal" },
          body: JSON.stringify({ status: "failed" }),
        }
      );
      const c = await invoiceContact(invoiceId);
      if (c && c.email) await sendEmail(c.email, "Your payment didn't go through",
        `Hi ${c.company},<br><br>Your bank payment of <b>${money(c.amount_cents)}</b> (invoice ${c.number}) couldn't be completed — usually insufficient funds or a bank rejection. No charge was made. You can retry anytime from your portal.`);
    } catch (e) {}
  }

  // Everything else (processing, payment_failed, etc.) we simply acknowledge.
  // Failed ACH leaves the invoice OPEN on purpose so you can follow up.
  return { statusCode: 200, body: JSON.stringify({ received: true }) };
};
