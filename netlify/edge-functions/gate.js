// Server-side access gate for the client demos (/betalab/ and /pelorus/).
// The password is read from the Netlify env var DEMO_PASSWORD — it is NOT stored
// in this file or the repo. Set it in: Site configuration -> Environment variables.

const COOKIE = "demo_auth";

async function sha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function formPage(error) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Client access &middot; Avi Data Technology</title>
<style>
  :root{--bg:#0A0E1A;--panel:#111726;--line:#1F2A44;--text:#EAF0FB;--muted:#8793AE;--brand:#6E8BFF;--mint:#34D8A0;--rose:#F2607D}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font-family:Inter,system-ui,-apple-system,sans-serif;padding:24px}
  .card{width:100%;max-width:380px;background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:28px;box-shadow:0 40px 120px -50px rgba(0,0,0,.9)}
  .mark{width:46px;height:46px;border-radius:13px;background:linear-gradient(150deg,var(--brand),var(--mint));display:grid;place-items:center;margin-bottom:16px}
  h1{font-size:19px;letter-spacing:-.02em;margin:0 0 6px}
  p{color:var(--muted);font-size:13px;line-height:1.55;margin:0 0 18px}
  label{display:block;font-family:ui-monospace,monospace;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:7px}
  input{width:100%;background:#0D1322;border:1px solid var(--line);border-radius:11px;color:var(--text);font-size:15px;padding:12px 14px;outline:none;transition:.16s}
  input:focus{border-color:var(--brand)}
  button{width:100%;margin-top:14px;border:none;border-radius:11px;padding:13px;font-size:14px;font-weight:700;color:#0a0e1a;background:linear-gradient(120deg,var(--brand),var(--mint));cursor:pointer}
  .err{color:var(--rose);font-size:12.5px;font-weight:600;margin-top:10px;min-height:14px}
</style></head>
<body><form class="card" method="POST" autocomplete="off">
  <div class="mark"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg></div>
  <h1>Client access</h1>
  <p>This area is private. Enter the access code provided by Avi Data Technology.</p>
  <label for="p">Access code</label>
  <input id="p" type="password" name="password" autofocus placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;">
  <button type="submit">Unlock &rarr;</button>
  <div class="err">${error || ""}</div>
</form></body></html>`;
}

export default async (request, context) => {
  const password = Deno.env.get("DEMO_PASSWORD");
  // Never fail open: if no password is configured, block access entirely.
  if (!password) {
    return new Response(
      "This area isn\u2019t configured yet. The site owner needs to set the DEMO_PASSWORD environment variable in Netlify.",
      { status: 503, headers: { "content-type": "text/plain; charset=utf-8" } }
    );
  }

  const expected = await sha256(password);
  const url = new URL(request.url);

  // Logout: clear the cookie.
  if (url.searchParams.has("logout")) {
    return new Response(null, {
      status: 302,
      headers: {
        location: url.pathname,
        "set-cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`,
      },
    });
  }

  // Already authorized → serve the real content.
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(new RegExp(COOKIE + "=([a-f0-9]+)"));
  if (match && match[1] === expected) {
    return context.next();
  }

  // Form submitted → verify.
  if (request.method === "POST") {
    const form = await request.formData();
    const tried = String(form.get("password") || "");
    if ((await sha256(tried)) === expected) {
      return new Response(null, {
        status: 302,
        headers: {
          location: url.pathname,
          "set-cookie": `${COOKIE}=${expected}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`,
        },
      });
    }
    return new Response(formPage("Incorrect code. Try again."), {
      status: 401,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  // Otherwise show the login form.
  return new Response(formPage(""), {
    status: 401,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
};

export const config = { path: ["/betalab", "/betalab/*", "/pelorus", "/pelorus/*"] };
