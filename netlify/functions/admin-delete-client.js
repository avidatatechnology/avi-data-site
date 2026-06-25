// Avi Data Technology — admin-delete-client
// ------------------------------------------------------------------
// Lets the OWNER permanently delete a client login and ALL their data
// (projects, invoices, tickets, notes — everything cascades from the
// auth user). Verifies the caller is an admin and refuses to delete
// another admin account. No npm dependencies (Node 18+).
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

  // Verify caller is signed in.
  const auth = event.headers.authorization || event.headers.Authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return json(401, { error: "Not signed in." });
  let userId;
  try {
    const u = await fetch(`${SUPABASE_URL}/auth/v1/user`, { headers: { apikey: ANON, Authorization: `Bearer ${token}` } });
    if (!u.ok) return json(401, { error: "Session expired." });
    userId = (await u.json()).id;
  } catch (e) { return json(401, { error: "Could not verify your session." }); }

  // Caller must be an admin.
  try {
    const p = await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}&select=role`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } });
    const row = (await p.json())[0];
    if (!row || row.role !== "admin") return json(403, { error: "Admins only." });
  } catch (e) { return json(500, { error: "Could not verify permissions." }); }

  // Inputs
  let clientId;
  try { clientId = (JSON.parse(event.body || "{}").client_id || "").trim(); } catch (e) { return json(400, { error: "Bad request." }); }
  if (!clientId) return json(400, { error: "Missing client." });
  if (clientId === userId) return json(400, { error: "You can't delete your own account." });

  // Never delete another admin from here.
  try {
    const p = await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(clientId)}&select=role`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } });
    const row = (await p.json())[0];
    if (row && row.role === "admin") return json(403, { error: "Can't delete an admin account here." });
  } catch (e) { return json(500, { error: "Could not verify the client." }); }

  // Delete the auth user — cascades to all their rows.
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${encodeURIComponent(clientId)}`, {
      method: "DELETE",
      headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` },
    });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      return json(400, { error: j.msg || j.error || "Could not delete the client." });
    }
  } catch (e) { return json(502, { error: "Could not reach the auth service." }); }

  return json(200, { ok: true });
};
