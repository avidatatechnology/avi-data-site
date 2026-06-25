// Avi Data Technology — maintenance-bill (scheduled)
// ------------------------------------------------------------------
// Runs on the 1st of each month. For every project on an ACTIVE
// maintenance plan that hasn't been billed yet this month, it creates
// a maintenance invoice the client can pay by ACH like any other.
// This is the pragmatic, low-risk way to do recurring billing without
// full Stripe Subscriptions — it reuses the existing pay flow.
//
// Netlify runs this automatically on the cron below. No npm (Node 18+).
// Env vars: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY.
// ------------------------------------------------------------------

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE_KEY;

const H = () => ({ apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}`, "Content-Type": "application/json" });

export default async () => {
  if (!SUPABASE_URL || !SERVICE_ROLE) return new Response("not configured", { status: 500 });

  const today = new Date();
  const monthStart = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, "0")}-01`;

  // Active plans not yet billed this month.
  let projects = [];
  try {
    const r = await fetch(
      `${SUPABASE_URL}/rest/v1/projects?maintenance_status=eq.active&maintenance_cents=gt.0` +
        `&select=id,client_id,name,maintenance_cents,maintenance_last_billed`,
      { headers: H() }
    );
    projects = await r.json();
  } catch (e) { return new Response("load failed", { status: 502 }); }

  // Current invoice count for numbering.
  let n = 0;
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/invoices?select=id`, { headers: { ...H(), Prefer: "count=exact", Range: "0-0" } });
    const cr = r.headers.get("content-range"); if (cr) n = parseInt(cr.split("/")[1], 10) || 0;
  } catch (e) {}

  let created = 0;
  for (const p of projects) {
    if (p.maintenance_last_billed && p.maintenance_last_billed >= monthStart) continue; // already billed this month
    n += 1;
    const number = "AVI-" + String(n).padStart(4, "0");
    try {
      const ins = await fetch(`${SUPABASE_URL}/rest/v1/invoices`, {
        method: "POST", headers: H(),
        body: JSON.stringify({
          client_id: p.client_id, project_id: p.id, number,
          description: "Monthly maintenance — " + (p.name || "project"),
          amount_cents: p.maintenance_cents, status: "open",
        }),
      });
      if (!ins.ok) { n -= 1; continue; }
      await fetch(`${SUPABASE_URL}/rest/v1/projects?id=eq.${encodeURIComponent(p.id)}`, {
        method: "PATCH", headers: { ...H(), Prefer: "return=minimal" },
        body: JSON.stringify({ maintenance_last_billed: monthStart }),
      });
      created += 1;
    } catch (e) { n -= 1; }
  }

  return new Response(JSON.stringify({ created }), { status: 200, headers: { "content-type": "application/json" } });
};

// Netlify scheduled function — 09:00 UTC on the 1st of every month.
export const config = { schedule: "0 9 1 * *" };
