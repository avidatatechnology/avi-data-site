// Avi Data Technology — admin-update-login
// ------------------------------------------------------------------
// Lets the OWNER change how a client signs in — either a real email
// or a username (stored as username@clients.avidatatechnology.com).
// Admin-verified. No npm (Node 18+).
// Env: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_ANON_KEY.
// ------------------------------------------------------------------

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ANON         = process.env.SUPABASE_ANON_KEY;
const LOGIN_DOMAIN = "clients.avidatatechnology.com";

function json(s, b) { return { statusCode: s, headers: { "content-type": "application/json" }, body: JSON.stringify(b) }; }

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });
  if (!SUPABASE_URL || !SERVICE_ROLE || !ANON) return json(500, { error: "Server not configured." });

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

  // Inputs
  let body;
  try { body = JSON.parse(event.body || "{}"); } catch (e) { return json(400, { error: "Bad request." }); }
  const clientId = (body.client_id || "").trim();
  let value = (body.value || "").trim();
  if (!clientId) return json(400, { error: "Missing client." });
  if (clientId === userId) return json(400, { error: "Change your own login from your account settings." });

  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) return json(400, { error: "That doesn't look like a valid email." });
  const newEmail = value.toLowerCase();
  const newUsername = null;
  const display = newEmail;

  // 1) Update the auth user's email (this is what they actually log in with).
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${encodeURIComponent(clientId)}`, {
      method: "PUT",
      headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}`, "Content-Type": "application/json" },
      body: JSON.stringify({ email: newEmail, email_confirm: true }),
    });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      const msg = (j.msg || j.error_description || j.error || "").toString();
      if (/registered|already|exists|duplicate/i.test(msg)) return json(400, { error: "That email is already used by another login." });
      return json(400, { error: msg || "Could not update the login." });
    }
  } catch (e) { return json(502, { error: "Could not reach the auth service." }); }

  // 2) Mirror onto the profile (email + username).
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(clientId)}`, {
      method: "PATCH",
      headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}`, "Content-Type": "application/json", Prefer: "return=minimal" },
      body: JSON.stringify({ email: newEmail, username: newUsername }),
    });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      if (/duplicate|unique/i.test(JSON.stringify(j))) return json(400, { error: "That username is already taken." });
      // Auth email already changed; report soft so the admin knows the login works.
      return json(200, { ok: true, display, warn: "Login updated, but the profile record didn't fully sync." });
    }
  } catch (e) { return json(200, { ok: true, display, warn: "Login updated." }); }

  return json(200, { ok: true, display });
};
