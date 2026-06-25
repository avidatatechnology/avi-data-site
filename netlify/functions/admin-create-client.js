// Avi Data Technology — admin-create-client
// ------------------------------------------------------------------
// Lets the OWNER (an admin) create a new client login from the admin
// console. Verifies the caller is actually an admin before doing
// anything, then creates the auth user via Supabase's Admin API and
// stamps their company name + email onto their profile.
// No npm dependencies (built-in fetch, Node 18+).
// ------------------------------------------------------------------

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ANON         = process.env.SUPABASE_ANON_KEY;

function json(statusCode, body) {
  return { statusCode, headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });
  if (!SUPABASE_URL || !SERVICE_ROLE || !ANON) return json(500, { error: "Server not configured." });

  // Who is calling?
  const auth = event.headers.authorization || event.headers.Authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return json(401, { error: "Not signed in." });

  let userId;
  try {
    const u = await fetch(`${SUPABASE_URL}/auth/v1/user`, { headers: { apikey: ANON, Authorization: `Bearer ${token}` } });
    if (!u.ok) return json(401, { error: "Session expired. Please sign in again." });
    userId = (await u.json()).id;
  } catch (e) { return json(401, { error: "Could not verify your session." }); }

  // Is the caller an admin? (Never trust the browser — check the database.)
  try {
    const p = await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}&select=role`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } });
    const row = (await p.json())[0];
    if (!row || row.role !== "admin") return json(403, { error: "Admins only." });
  } catch (e) { return json(500, { error: "Could not verify permissions." }); }

  // Inputs
  let body;
  try { body = JSON.parse(event.body || "{}"); } catch (e) { return json(400, { error: "Bad request." }); }
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";
  const company = (body.company_name || "").trim();
  if (!email || !password) return json(400, { error: "Email and password are required." });
  if (password.length < 8) return json(400, { error: "Password must be at least 8 characters." });

  // Create the login (email_confirm:true so they can sign in right away).
  let newId;
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
      method: "POST",
      headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}`, "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, email_confirm: true })
    });
    const j = await r.json();
    if (!r.ok) return json(400, { error: j.msg || j.error_description || j.error || "Could not create login." });
    newId = j.id || (j.user && j.user.id);
  } catch (e) { return json(502, { error: "Could not reach the auth service." }); }

  // Stamp company name + email onto the auto-created profile, and make
  // this user the OWNER of their own account (client_id = their own id).
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(newId)}`, {
      method: "PATCH",
      headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}`, "Content-Type": "application/json", Prefer: "return=minimal" },
      body: JSON.stringify({ company_name: company || null, email, client_id: newId })
    });
  } catch (e) { /* non-fatal */ }

  return json(200, { ok: true, id: newId });
};
