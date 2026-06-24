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

  // payment succeeded -> mark the invoice paid (from open or processing).
  // The status filter makes retries / duplicates harmless.
  if (evt.type === "payment_intent.succeeded" && invoiceId) {
    try {
      await fetch(
        `${SUPABASE_URL}/rest/v1/invoices?id=eq.${encodeURIComponent(invoiceId)}&status=in.(open,processing)`,
        {
          method: "PATCH",
          headers: {
            apikey: SERVICE_ROLE,
            Authorization: `Bearer ${SERVICE_ROLE}`,
            "Content-Type": "application/json",
            Prefer: "return=minimal",
          },
          body: JSON.stringify({ status: "paid", paid_at: new Date().toISOString() }),
        }
      );
    } catch (e) { /* Stripe stays the source of truth; it will retry on a non-2xx */ }
  }

  // ACH failed/returned (e.g. insufficient funds) -> put it back to "open"
  // so it shows as due again and the client can retry.
  if (evt.type === "payment_intent.payment_failed" && invoiceId) {
    try {
      await fetch(
        `${SUPABASE_URL}/rest/v1/invoices?id=eq.${encodeURIComponent(invoiceId)}&status=eq.processing`,
        {
          method: "PATCH",
          headers: {
            apikey: SERVICE_ROLE,
            Authorization: `Bearer ${SERVICE_ROLE}`,
            "Content-Type": "application/json",
            Prefer: "return=minimal",
          },
          body: JSON.stringify({ status: "open" }),
        }
      );
    } catch (e) { /* ignore */ }
  }

  // Everything else (processing, payment_failed, etc.) we simply acknowledge.
  // Failed ACH leaves the invoice OPEN on purpose so you can follow up.
  return { statusCode: 200, body: JSON.stringify({ received: true }) };
};
