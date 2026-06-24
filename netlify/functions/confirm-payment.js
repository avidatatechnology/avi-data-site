// Avi Data Technology — confirm-payment
// ------------------------------------------------------------------
// After the client submits payment, this re-checks the PaymentIntent
// directly with Stripe (the source of truth) and marks the invoice
// paid ONLY if it genuinely succeeded.
//   • Card  -> "succeeded" instantly  -> invoice marked PAID
//   • ACH   -> "processing" for a few business days -> stays OPEN
//             (you'll see it land in Stripe; the optional webhook
//              upgrade later flips it to PAID automatically on clear)
// No npm dependencies: built-in fetch() on Node 18+.
// ------------------------------------------------------------------

const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
const SUPABASE_URL  = process.env.SUPABASE_URL;
const SERVICE_ROLE  = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ANON          = process.env.SUPABASE_ANON_KEY;

function json(statusCode, body) {
  return {
    statusCode,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });
  if (!STRIPE_SECRET || !SUPABASE_URL || !SERVICE_ROLE || !ANON) {
    return json(500, { error: "Server not configured. Check Netlify environment variables." });
  }

  // Verify session.
  const auth = event.headers.authorization || event.headers.Authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return json(401, { error: "Not signed in." });

  let userId;
  try {
    const ures = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: { apikey: ANON, Authorization: `Bearer ${token}` },
    });
    if (!ures.ok) return json(401, { error: "Session expired. Please sign in again." });
    userId = (await ures.json()).id;
  } catch (e) {
    return json(401, { error: "Could not verify your session." });
  }

  // Inputs.
  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch (e) {
    return json(400, { error: "Bad request." });
  }
  const invoiceId = payload.invoice_id;
  const paymentIntentId = payload.payment_intent_id;
  if (!invoiceId || !paymentIntentId) return json(400, { error: "Missing payment details." });

  // Confirm the caller owns this invoice.
  let invoice;
  try {
    const ires = await fetch(
      `${SUPABASE_URL}/rest/v1/invoices?id=eq.${encodeURIComponent(invoiceId)}` +
        `&select=id,client_id,status`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    invoice = (await ires.json())[0];
  } catch (e) {
    return json(500, { error: "Could not load the invoice." });
  }
  if (!invoice) return json(404, { error: "Invoice not found." });
  if (invoice.client_id !== userId) return json(403, { error: "This invoice isn't on your account." });

  // Ask Stripe what actually happened.
  let pi;
  try {
    const sres = await fetch(
      `https://api.stripe.com/v1/payment_intents/${encodeURIComponent(paymentIntentId)}`,
      { headers: { Authorization: `Bearer ${STRIPE_SECRET}` } }
    );
    pi = await sres.json();
    if (!sres.ok) return json(502, { error: (pi.error && pi.error.message) || "Could not verify payment." });
  } catch (e) {
    return json(502, { error: "Could not reach the payment processor." });
  }

  // The PaymentIntent must belong to THIS invoice.
  if (!pi.metadata || pi.metadata.invoice_id !== invoice.id) {
    return json(409, { error: "Payment does not match this invoice." });
  }

  if (pi.status === "succeeded") {
    // Mark paid. The &status=eq.open guard makes repeat calls harmless.
    try {
      await fetch(
        `${SUPABASE_URL}/rest/v1/invoices?id=eq.${encodeURIComponent(invoice.id)}&status=eq.open`,
        {
          method: "PATCH",
          headers: {
            apikey: SERVICE_ROLE,
            Authorization: `Bearer ${SERVICE_ROLE}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ status: "paid", paid_at: new Date().toISOString() }),
        }
      );
    } catch (e) { /* Stripe remains the source of truth */ }
    return json(200, { status: "paid" });
  }

  if (pi.status === "processing") {
    // ACH bank debit submitted; clears in a few business days. Mark the
    // invoice "processing" so the client sees a Pending status (not "due").
    try {
      await fetch(
        `${SUPABASE_URL}/rest/v1/invoices?id=eq.${encodeURIComponent(invoice.id)}&status=eq.open`,
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
    } catch (e) { /* non-fatal; webhook is the backstop */ }
    return json(200, { status: "processing" });
  }

  return json(200, { status: pi.status || "incomplete" });
};
