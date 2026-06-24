// Avi Data Technology — create-payment-intent
// ------------------------------------------------------------------
// Creates a Stripe PaymentIntent for ONE invoice the logged-in client
// owns. ACH (US bank debit) ONLY — no card, no Klarna, no wallets.
// No npm dependencies: uses built-in fetch() (Node 18+).
// Secret keys come from Netlify environment variables — never the repo.
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

  // 1. Who is calling? Verify their Supabase session token.
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

  // 2. Which invoice?
  let invoiceId;
  try {
    invoiceId = JSON.parse(event.body || "{}").invoice_id;
  } catch (e) {
    return json(400, { error: "Bad request." });
  }
  if (!invoiceId) return json(400, { error: "Missing invoice." });

  // 3. Load it (service role bypasses RLS) and verify ownership.
  let invoice;
  try {
    const ires = await fetch(
      `${SUPABASE_URL}/rest/v1/invoices?id=eq.${encodeURIComponent(invoiceId)}` +
        `&select=id,client_id,number,description,amount_cents,currency,status`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    invoice = (await ires.json())[0];
  } catch (e) {
    return json(500, { error: "Could not load the invoice." });
  }
  if (!invoice) return json(404, { error: "Invoice not found." });
  if (invoice.client_id !== userId) return json(403, { error: "This invoice isn't on your account." });
  if (invoice.status !== "open") return json(409, { error: "This invoice is already settled." });

  // 4. Create the PaymentIntent — ACH ONLY.
  //    Explicit payment_method_types (NOT automatic_payment_methods) guarantees
  //    the Payment Element shows bank debit only — never card / Klarna / wallets.
  let pi;
  try {
    const body = new URLSearchParams();
    body.set("amount", String(invoice.amount_cents));
    body.set("currency", invoice.currency || "usd");
    body.set("payment_method_types[]", "us_bank_account");
    body.set("payment_method_options[us_bank_account][verification_method]", "automatic");
    body.set("description", `${invoice.number} — ${invoice.description}`);
    body.set("metadata[invoice_id]", invoice.id);

    const sres = await fetch("https://api.stripe.com/v1/payment_intents", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${STRIPE_SECRET}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    });
    pi = await sres.json();
    if (!sres.ok) return json(502, { error: (pi.error && pi.error.message) || "Payment setup failed." });
  } catch (e) {
    return json(502, { error: "Could not reach the payment processor." });
  }

  // 5. Record which PaymentIntent belongs to this invoice (non-fatal).
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/invoices?id=eq.${encodeURIComponent(invoice.id)}`, {
      method: "PATCH",
      headers: {
        apikey: SERVICE_ROLE,
        Authorization: `Bearer ${SERVICE_ROLE}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ stripe_payment_intent_id: pi.id }),
    });
  } catch (e) { /* ignore */ }

  // 6. Hand the browser what it needs to render the ACH form.
  return json(200, {
    client_secret: pi.client_secret,
    amount_cents: invoice.amount_cents,
    number: invoice.number,
  });
};
