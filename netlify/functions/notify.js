// Avi Data Technology — notify
// ------------------------------------------------------------------
// Sends a branded notification email to a client. Admin-triggered
// (invoice issued, ticket reply). Uses Resend's HTTP API — no SMTP,
// no npm. Fails soft: if email isn't configured, returns ok:false but
// never blocks the app. Node 18+.
//
// Env vars: RESEND_API_KEY, EMAIL_FROM (e.g. "Avi Data <hello@avidatatechnology.com>"),
//   PORTAL_URL (e.g. https://avidatatechnology.com/portal/),
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_ANON_KEY.
// ------------------------------------------------------------------

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM     = process.env.EMAIL_FROM || "Avi Data Technology <hello@avidatatechnology.com>";
const PORTAL_URL     = process.env.PORTAL_URL || "https://avidatatechnology.com/portal/";
const SUPABASE_URL   = process.env.SUPABASE_URL;
const SERVICE_ROLE   = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ANON           = process.env.SUPABASE_ANON_KEY;

function json(s, b) { return { statusCode: s, headers: { "content-type": "application/json" }, body: JSON.stringify(b) }; }

function shell(title, body) {
  return `<div style="background:#0A0E1A;padding:32px 0;font-family:-apple-system,Inter,Arial,sans-serif">
    <div style="max-width:480px;margin:0 auto;background:#111726;border:1px solid #1F2A44;border-radius:16px;padding:32px;color:#EAF0FB">
      <div style="font-family:Arial;font-weight:800;font-size:18px;margin-bottom:20px">Avi Data <span style="color:#8793AE;font-weight:600">Technology</span></div>
      <h1 style="font-size:20px;margin:0 0 14px">${title}</h1>
      <div style="color:#C7D0E4;font-size:14px;line-height:1.6">${body}</div>
      <a href="${PORTAL_URL}" style="display:inline-block;margin-top:24px;background:#6E8BFF;color:#fff;text-decoration:none;padding:12px 22px;border-radius:10px;font-weight:700;font-size:14px">Open your portal</a>
      <div style="margin-top:26px;color:#566179;font-size:12px">hello@avidatatechnology.com</div>
    </div></div>`;
}

async function sendEmail(to, subject, html) {
  if (!RESEND_API_KEY) return false;
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: EMAIL_FROM, to, subject, html }),
    });
    return r.ok;
  } catch (e) { return false; }
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });
  if (!SUPABASE_URL || !SERVICE_ROLE || !ANON) return json(500, { error: "Server not configured." });

  // Admin check.
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
  const { kind, client_id } = body;
  if (!client_id) return json(400, { error: "Missing client." });

  // Resolve the client's email (real email, or skip synthetic username logins).
  let email = null, company = "there";
  try {
    const p = await fetch(`${SUPABASE_URL}/rest/v1/profiles?id=eq.${encodeURIComponent(client_id)}&select=email,company_name,username`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } });
    const row = (await p.json())[0] || {};
    company = row.company_name || "there";
    // Username logins use a synthetic @clients.avidatatechnology.com address — don't email those.
    if (row.email && !/@clients\.avidatatechnology\.com$/i.test(row.email)) email = row.email;
  } catch (e) {}
  if (!email) return json(200, { ok: false, reason: "no-email" });

  let subject, inner;
  if (kind === "invoice_issued") {
    const amt = body.amount || "";
    subject = "A new invoice from Avi Data Technology";
    inner = `Hi ${company},<br><br>A new invoice${amt ? " for <b>" + amt + "</b>" : ""} is ready in your portal. You can review and pay it securely by bank transfer.`;
  } else if (kind === "ticket_reply") {
    subject = "We replied to your support ticket";
    inner = `Hi ${company},<br><br>We've responded to your support ticket. Open your portal to read our reply and continue the conversation.`;
  } else {
    return json(400, { error: "Unknown notification type." });
  }

  const ok = await sendEmail(email, subject, shell(subject, inner));
  return json(200, { ok });
};
