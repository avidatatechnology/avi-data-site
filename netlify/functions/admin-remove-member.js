// Avi Data Technology — admin-remove-member
// ------------------------------------------------------------------
// Removes ONE extra user login from a client account (not the account
// owner — use Delete client for the whole account). Admin-verified.
// No npm (Node 18+).
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
  const memberId = (body.user_id || "").trim();
  if (!memberId) return json(400, { error: "Missing user." });

  // Look up the target. Must be a non-admin member (id != its own account id).
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(memberId)}&select=role,client_id`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } });
    const row = (await r.json())[0];
    if (!row) return json(400, { error: "User not found." });
    if (row.role === "admin") return json(403, { error: "Can't remove an admin." });
    if (!row.client_id || row.client_id === memberId) return json(400, { error: "That's the account owner — use Delete client to remove the whole account." });
  } catch (e) { return json(500, { error: "Could not verify the user." }); }

  // Delete the auth user (their profile cascades).
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${encodeURIComponent(memberId)}`, {
      method: "DELETE",
      headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` },
    });
    if (!r.ok) { const j = await r.json().catch(() => ({})); return json(400, { error: j.msg || "Could not remove the user." }); }
  } catch (e) { return json(502, { error: "Could not reach the auth service." }); }

  return json(200, { ok: true });
};
