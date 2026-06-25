// Avi Data Technology — admin-add-member
// ------------------------------------------------------------------
// Adds an EXTRA user login to an existing client account. The new
// user shares the account's projects/invoices (profile.client_id =
// account id). Admin-verified. No npm (Node 18+).
// ------------------------------------------------------------------

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ANON         = process.env.SUPABASE_ANON_KEY;

function json(s, b) { return { statusCode: s, headers: { "content-type": "application/json" }, body: JSON.stringify(b) }; }

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });
  if (!SUPABASE_URL || !SERVICE_ROLE || !ANON) return json(500, { error: "Server not configured." });

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

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch (e) { return json(400, { error: "Bad request." }); }
  const accountId = (body.account_id || "").trim();
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";
  const contact = (body.contact_name || "").trim();
  if (!accountId) return json(400, { error: "Missing account." });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json(400, { error: "Enter a valid email." });
  if (password.length < 8) return json(400, { error: "Password must be at least 8 characters." });

  // Pull the account's company name so the new user shows it too.
  let company = null;
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(accountId)}&select=company_name`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } });
    const row = (await r.json())[0]; if (!row) return json(400, { error: "Account not found." });
    company = row.company_name || null;
  } catch (e) { return json(500, { error: "Could not load the account." }); }

  // Create the auth user.
  let newId;
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
      method: "POST",
      headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}`, "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, email_confirm: true }),
    });
    const j = await r.json();
    if (!r.ok) return json(400, { error: j.msg || j.error_description || j.error || "Could not create the user." });
    newId = j.id || (j.user && j.user.id);
  } catch (e) { return json(502, { error: "Could not reach the auth service." }); }

  // Point their profile at the account.
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(newId)}`, {
      method: "PATCH",
      headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}`, "Content-Type": "application/json", Prefer: "return=minimal" },
      body: JSON.stringify({ role: "client", client_id: accountId, company_name: company, email, contact_name: contact || null }),
    });
  } catch (e) { /* user exists; profile sync best-effort */ }

  return json(200, { ok: true, id: newId });
};
