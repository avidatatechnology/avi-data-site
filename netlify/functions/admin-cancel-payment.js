// Avi Data Technology — admin-cancel-payment
// ------------------------------------------------------------------
// When the OWNER voids an invoice, this tries to cancel its Stripe
// PaymentIntent so no bank debit goes through. Honest limits:
//   • Not yet submitted (incomplete) -> canceled cleanly.
//   • Already "processing" (ACH in flight) or "succeeded" -> CANNOT be
//     canceled; the money is moving. You must refund in Stripe instead.
// Admin-verified. No npm dependencies (Node 18+).
// ------------------------------------------------------------------

const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
const SUPABASE_URL  = process.env.SUPABASE_URL;
const SERVICE_ROLE  = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ANON          = process.env.SUPABASE_ANON_KEY;

function json(statusCode, body) {
  return { statusCode, headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });
  if (!STRIPE_SECRET || !SUPABASE_URL || !SERVICE_ROLE || !ANON) return json(500, { error: "Server not configured." });

  // Verify caller is an admin.
  const auth = event.headers.authorization || event.headers.Authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return json(401, { error: "Not signed in." });
  let userId;
  try {
    const u = await fetch(`${SUPABASE_URL}/auth/v1/user`, { headers: { apikey: ANON, Authorization: `Bearer ${token}` } });
    if (!u.ok) return json(401, { error: "Session expired." });
    userId = (await u.json()).id;
  } catch (e) { return json(401, { error: "Could not verify your session." }); }
  try {
    const p = await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}&select=role`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } });
    const row = (await p.json())[0];
    if (!row || row.role !== "admin") return json(403, { error: "Admins only." });
  } catch (e) { return json(500, { error: "Could not verify permissions." }); }

  // Which invoice?
  let invoiceId;
  try { invoiceId = JSON.parse(event.body || "{}").invoice_id; } catch (e) { return json(400, { error: "Bad request." }); }
  if (!invoiceId) return json(400, { error: "Missing invoice." });

  // Look up its PaymentIntent id.
  let piId = null;
  try {
    const ires = await fetch(
      `${SUPABASE_URL}/rest/v1/invoices?id=eq.${encodeURIComponent(invoiceId)}&select=stripe_payment_intent_id`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    piId = ((await ires.json())[0] || {}).stripe_payment_intent_id || null;
  } catch (e) { /* fall through */ }

  // No payment was ever started — nothing to cancel.
  if (!piId) return json(200, { canceled: false, reason: "none" });

  // Check the PaymentIntent's state.
  let pi;
  try {
    const sres = await fetch(`https://api.stripe.com/v1/payment_intents/${encodeURIComponent(piId)}`,
      { headers: { Authorization: `Bearer ${STRIPE_SECRET}` } });
    pi = await sres.json();
    if (!sres.ok) return json(200, { canceled: false, reason: "lookup_failed" });
  } catch (e) { return json(200, { canceled: false, reason: "unreachable" }); }

  if (pi.status === "succeeded") return json(200, { canceled: false, reason: "succeeded" });
  if (pi.status === "processing") return json(200, { canceled: false, reason: "processing" });
  if (pi.status === "canceled")  return json(200, { canceled: true, reason: "already" });

  // Cancelable states: requires_payment_method / _confirmation / _action / _capture.
  try {
    const cres = await fetch(`https://api.stripe.com/v1/payment_intents/${encodeURIComponent(piId)}/cancel`,
      { method: "POST", headers: { Authorization: `Bearer ${STRIPE_SECRET}`, "Content-Type": "application/x-www-form-urlencoded" } });
    const cj = await cres.json();
    if (!cres.ok) return json(200, { canceled: false, reason: (cj.error && cj.error.code) || "cancel_failed" });
    return json(200, { canceled: true, reason: "canceled" });
  } catch (e) {
    return json(200, { canceled: false, reason: "unreachable" });
  }
};
