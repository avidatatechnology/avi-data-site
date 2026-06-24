// Avi Data Technology — admin-set-password
// ------------------------------------------------------------------
// Lets the OWNER (an admin) set a new password for a client login.
// Verifies the caller is an admin, then updates the target user's
// password via Supabase's Admin API. No npm dependencies (Node 18+).
// Secret keys come from Netlify environment variables — never the repo.
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
  const clientId = (body.client_id || "").trim();
  const password = body.password || "";
  if (!clientId) return json(400, { error: "Missing client." });
  if (password.length < 8) return json(400, { error: "Password must be at least 8 characters." });

  // Safety: only allow resetting an actual client (role 'client' or null), never another admin.
  try {
    const p = await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(clientId)}&select=role`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } });
    const row = (await p.json())[0];
    if (!row) return json(404, { error: "Client not found." });
    if (row.role === "admin") return json(403, { error: "Can't reset an admin account here." });
  } catch (e) { return json(500, { error: "Could not verify the client." }); }

  // Update the password via the Admin API.
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${encodeURIComponent(clientId)}`, {
      method: "PUT",
      headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}`, "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    const j = await r.json();
    if (!r.ok) return json(400, { error: j.msg || j.error_description || j.error || "Could not update the password." });
  } catch (e) { return json(502, { error: "Could not reach the auth service." }); }

  return json(200, { ok: true });
};
