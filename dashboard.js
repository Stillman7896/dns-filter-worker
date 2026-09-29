import { normalizeDomain } from './rules.js';

const SESSION_COOKIE = 'dns_dash_session';

function isConfigured(env) {
  return typeof env.DASHBOARD_PASSWORD === 'string' && env.DASHBOARD_PASSWORD.length > 0;
}

/** Constant-time-ish string compare. */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Session is valid only if the cookie matches the configured password. */
function authOk(request, env) {
  const cookie = request.headers.get('cookie') || '';
  const m = cookie.match(/(?:^|;\s*)dns_dash_session=([^;]+)/);
  if (!m) return false;
  return safeEqual(decodeURIComponent(m[1]), env.DASHBOARD_PASSWORD);
}

function json(body, init = {}) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...(init.headers || {}),
    },
  });
}

export async function handleApi(request, env, url, rules) {
  // ---- Login: POST /api/session { password } or Authorization: Bearer <pw> ----
  if (url.pathname === '/api/session' && request.method === 'POST') {
    if (!isConfigured(env)) {
      return json({ error: 'Password not configured', code: 'unconfigured' }, { status: 503 });
    }

    let password = null;
    const auth = request.headers.get('authorization') || '';
    if (auth.startsWith('Bearer ')) password = auth.slice(7);
    if (!password) {
      try {
        const b = await request.json();
        if (b && typeof b.password === 'string') password = b.password;
      } catch {}
    }
    if (!password || !safeEqual(password, env.DASHBOARD_PASSWORD)) {
      return json({ error: 'Invalid password' }, { status: 401 });
    }

    const res = json({ ok: true });
    res.headers.append(
      'Set-Cookie',
      `${SESSION_COOKIE}=${encodeURIComponent(env.DASHBOARD_PASSWORD)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`
    );
    return res;
  }

  // ---- Everything else requires a valid session ----
  if (!isConfigured(env)) {
    return json({ error: 'Password not configured', code: 'unconfigured' }, { status: 503 });
  }
  if (!authOk(request, env)) {
    // No WWW-Authenticate header -> the browser will NOT show its native
    // username/password dialog. The UI handles 401 itself.
    return json({ error: 'Unauthorized' }, { status: 401 });
  }

  const path = url.pathname;

  if (path === '/api/rules' && request.method === 'GET') {
    await rules.refresh(true);
    return json({ rules: await rules.list() });
  }

  if (path === '/api/rules' && request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'bad json' }, { status: 400 }); }

    const domain = normalizeDomain(body.domain);
    if (!domain) return json({ error: 'invalid domain' }, { status: 400 });
    if (body.kind !== 'allow' && body.kind !== 'deny') {
      return json({ error: 'kind must be allow|deny' }, { status: 400 });
    }

    await rules.put(domain, body.kind);
    return json({ ok: true, domain, kind: body.kind });
  }

  if (path === '/api/rules' && request.method === 'DELETE') {
    const domain = normalizeDomain(url.searchParams.get('domain') || '');
    if (!domain) return json({ error: 'invalid domain' }, { status: 400 });
    const existed = await rules.delete(domain);
    return json({ ok: true, existed });
  }

  if (path === '/api/rules/bulk' && request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'bad json' }, { status: 400 }); }
    if (body.kind !== 'allow' && body.kind !== 'deny') {
      return json({ error: 'kind must be allow|deny' }, { status: 400 });
    }
    if (typeof body.domains !== 'string') {
      return json({ error: 'domains must be a string' }, { status: 400 });
    }

    const added = [], skipped = [];
    const lines = body.domains.split(/[\r\n,]+/);
    for (const line of lines) {
      const d = normalizeDomain(line);
      if (d) added.push(d); else if (line.trim()) skipped.push(line.trim());
    }
    const unique = [...new Set(added)];
    await Promise.all(unique.map((d) => rules.put(d, body.kind)));
    return json({ ok: true, added: unique.length, skipped });
  }

  // ---- logs (D1) ----
  const logs = env.LOGS;

  // DELETE /api/logs/:id  -> delete one row
  if (path.startsWith('/api/logs/') && request.method === 'DELETE') {
    const id = path.slice('/api/logs/'.length);
    if (!/^\d+$/.test(id)) return json({ error: 'bad id' }, { status: 400 });
    await logs.prepare('DELETE FROM dns_logs WHERE id = ?').bind(parseInt(id, 10)).run();
    return json({ ok: true });
  }

  if (path === '/api/logs') {
    const search = (url.searchParams.get('search') || '').trim();
    const status = url.searchParams.get('status') || '';

    // GET /api/logs?search=&status=&limit=&offset=
    if (request.method === 'GET') {
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10) || 100, 500);
      const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);

      let where = '';
      const args = [];
      if (search) { where += ' WHERE domain LIKE ?'; args.push('%' + search + '%'); }
      if (status) { where += (where ? ' AND' : ' WHERE') + ' status = ?'; args.push(status); }

      const total = (await logs.prepare('SELECT COUNT(*) AS n FROM dns_logs' + where).bind(...args).first()).n;
      const { results } = await logs
        .prepare('SELECT id, domain, status, filter, ts FROM dns_logs' + where + ' ORDER BY ts DESC LIMIT ? OFFSET ?')
        .bind(...args, limit, offset)
        .all();

      return json({ logs: results, total });
    }

    // DELETE /api/logs?search=&status=&clear=1  -> delete matching (or all with clear=1)
    if (request.method === 'DELETE') {
      let where = '';
      const args = [];
      if (search) { where += ' WHERE domain LIKE ?'; args.push('%' + search + '%'); }
      if (status) { where += (where ? ' AND' : ' WHERE') + ' status = ?'; args.push(status); }

      if (!where && url.searchParams.get('clear') !== '1') {
        return json({ error: 'use ?clear=1 to delete all logs' }, { status: 400 });
      }

      await logs.prepare('DELETE FROM dns_logs' + where).bind(...args).run();
      return json({ ok: true });
    }
  }

  return json({ error: 'not found' }, { status: 404 });
}

export function serveDashboard() {
  return new Response(DASHBOARD_HTML, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy':
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
    },
  });
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNS Filter — Rules</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3; --muted:#8b949e;
          --green:#3fb950; --red:#f85149; --blue:#58a6ff; --yellow:#d29922; }
  * { box-sizing: border-box; }
  body { margin:0; font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
         background:var(--bg); color:var(--fg); }
  header { padding:16px 24px; border-bottom:1px solid var(--border); display:flex;
           align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap; }
  h1 { font-size:16px; margin:0; font-weight:600; }
  h1 small { color:var(--muted); font-weight:400; margin-left:8px; }
  main { max-width:960px; margin:0 auto; padding:24px; }
  .row { display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; }
  input, select, textarea, button {
    font:inherit; background:var(--panel); color:var(--fg);
    border:1px solid var(--border); border-radius:6px; padding:8px 12px;
  }
  input[type=text], input[type=password] { flex:1; min-width:220px; }
  textarea { width:100%; min-height:100px; font-family:ui-monospace,monospace; }
  button { cursor:pointer; background:var(--blue); border-color:transparent; color:#fff; font-weight:600; }
  button.ghost { background:transparent; border-color:var(--border); color:var(--fg); font-weight:400; }
  button.danger { background:transparent; border-color:var(--red); color:var(--red); }
  button:hover { filter:brightness(1.1); }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:20px; max-width:420px; }
  table { width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  th, td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--border); }
  th { background:#0f141b; font-weight:600; font-size:12px; text-transform:uppercase;
       letter-spacing:0.05em; color:var(--muted); }
  tr:last-child td { border-bottom:none; }
  .pill { display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; font-weight:600; }
  .pill.allow { background:rgba(63,185,80,0.15); color:var(--green); }
  .pill.deny  { background:rgba(248,81,73,0.15); color:var(--red); }
  .pill.allowed { background:rgba(63,185,80,0.15); color:var(--green); }
  .pill.blocked { background:rgba(248,81,73,0.15); color:var(--red); }
  .muted { color:var(--muted); }
  .tabs { display:flex; gap:4px; margin-bottom:16px; }
  .tab { padding:8px 16px; border-radius:6px; cursor:pointer; border:1px solid transparent;
         background:transparent; color:var(--muted); }
  .tab.active { background:var(--panel); border-color:var(--border); color:var(--fg); }
  .hidden { display:none; }
  .flex { display:flex; gap:8px; align-items:center; }
  .flex-grow { flex:1; }
  #status { min-height:22px; margin:8px 0; font-size:13px; }
  #status.err { color:var(--red); }
  #status.ok { color:var(--green); }
  code { background:var(--panel); padding:2px 6px; border-radius:4px; font-size:12px; }
  .banner { background:rgba(210,153,34,0.12); border:1px solid var(--yellow); color:var(--yellow);
            padding:12px 14px; border-radius:6px; margin-bottom:16px; }
</style>
</head>
<body>
<header>
  <h1>DNS Filter <small class="muted">custom rules</small></h1>
  <div class="flex">
    <span id="auth-status" class="muted"></span>
    <button id="logout" class="ghost hidden">Sign out</button>
  </div>
</header>

<main>
  <div id="unconfigured-view" class="hidden">
    <div class="card">
      <h2 style="margin-top:0;">Dashboard disabled</h2>
      <p>No <code>DASHBOARD_PASSWORD</code> secret is configured. Set it to enable rule management:</p>
      <pre style="background:var(--panel);border:1px solid var(--border);padding:10px;border-radius:6px;overflow:auto;">wrangler secret put DASHBOARD_PASSWORD</pre>
      <p class="muted">DoH filtering still works without it — only the dashboard is disabled.</p>
    </div>
  </div>

  <div id="login-view" class="hidden">
    <div class="card">
      <h2 style="margin-top:0;">Sign in</h2>
      <p class="muted">Manage custom allow/deny rules.</p>
      <div class="row">
        <input type="password" id="pw" placeholder="Dashboard password" autocomplete="current-password">
        <button id="login-btn">Sign in</button>
      </div>
    </div>
  </div>

  <div id="app-view" class="hidden">
    <div class="tabs">
      <button class="tab active" data-tab="single">Add rule</button>
      <button class="tab" data-tab="bulk">Bulk import</button>
      <button class="tab" data-tab="test">Test domain</button>
      <button class="tab" data-tab="logs">Logs</button>
    </div>

    <section id="tab-single" class="tab-panel">
      <div class="row">
        <input type="text" id="domain" placeholder="example.com (blocks *.example.com)">
        <select id="kind">
          <option value="deny">Deny</option>
          <option value="allow">Allow</option>
        </select>
        <button id="add">Add</button>
      </div>
      <p class="muted">Allow always wins over deny and over the remote blocklist.</p>
    </section>

    <section id="tab-bulk" class="tab-panel hidden">
      <div class="row">
        <select id="bulk-kind">
          <option value="deny">Deny</option>
          <option value="allow">Allow</option>
        </select>
        <button id="bulk-add">Import</button>
      </div>
      <textarea id="bulk-domains" placeholder="One domain per line…"></textarea>
      <p class="muted">Comma or newline separated. Wildcards (<code>*.example.com</code>) and
         full URLs are accepted and normalized.</p>
    </section>

    <section id="tab-test" class="tab-panel hidden">
      <div class="row">
        <input type="text" id="test-domain" placeholder="sub.example.com">
        <button id="test-btn">Test</button>
      </div>
      <div id="test-result" class="muted"></div>
    </section>

    <div id="status"></div>

    <div class="flex" style="margin:16px 0 8px;">
      <h2 class="flex-grow" style="font-size:14px;margin:0;">Rules</h2>
      <input type="text" id="filter" placeholder="Filter…" style="max-width:220px;">
    </div>
    <table>
      <thead><tr><th>Domain</th><th>Kind</th><th></th></tr></thead>
      <tbody id="rules-body"><tr><td colspan="3" class="muted">Loading…</td></tr></tbody>
    </table>
  </div>
</main>

<script>
const $ = (id) => document.getElementById(id);
let RULES = [];

function setStatus(msg, kind) {
  const el = $('status');
  el.textContent = msg || '';
  el.className = kind || '';
  if (msg) setTimeout(() => { if (el.textContent === msg) el.textContent = ''; }, 4000);
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (res.status === 401) { showLogin(); throw new Error('unauthorized'); }
  if (res.status === 503) { showUnconfigured(); throw new Error('unconfigured'); }
  if (!res.ok) {
    const t = await res.text();
    throw new Error(t || 'HTTP ' + res.status);
  }
  return res.status === 204 ? null : res.json();
}

function showLogin() {
  $('unconfigured-view').classList.add('hidden');
  $('login-view').classList.remove('hidden');
  $('app-view').classList.add('hidden');
  $('logout').classList.add('hidden');
  $('auth-status').textContent = '';
}
function showUnconfigured() {
  $('login-view').classList.add('hidden');
  $('app-view').classList.add('hidden');
  $('unconfigured-view').classList.remove('hidden');
  $('logout').classList.add('hidden');
  $('auth-status').textContent = '';
}
function showApp() {
  $('login-view').classList.add('hidden');
  $('unconfigured-view').classList.add('hidden');
  $('app-view').classList.remove('hidden');
  $('logout').classList.remove('hidden');
  $('auth-status').textContent = 'signed in';
  loadRules();
}

async function loadRules() {
  try {
    const data = await api('/api/rules');
    RULES = data.rules || [];
    render();
  } catch (e) {
    if (e.message !== 'unauthorized' && e.message !== 'unconfigured') setStatus(e.message, 'err');
  }
}

function render() {
  const filter = ($('filter').value || '').toLowerCase();
  const tbody = $('rules-body');
  const filtered = RULES.filter((r) => r.domain.includes(filter));
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="3" class="muted">' +
      (RULES.length ? 'No matches.' : 'No custom rules yet.') + '</td></tr>';
    return;
  }
  const frag = document.createDocumentFragment();
  for (const r of filtered) {
    const tr = document.createElement('tr');
    const td1 = document.createElement('td');
    td1.textContent = r.domain;
    const td2 = document.createElement('td');
    const pill = document.createElement('span');
    pill.className = 'pill ' + r.kind;
    pill.textContent = r.kind;
    td2.appendChild(pill);
    const td3 = document.createElement('td');
    td3.style.textAlign = 'right';
    const del = document.createElement('button');
    del.className = 'danger';
    del.textContent = 'Delete';
    del.onclick = async () => {
      try {
        await api('/api/rules?domain=' + encodeURIComponent(r.domain), { method: 'DELETE' });
        setStatus('Deleted ' + r.domain, 'ok');
        loadRules();
      } catch (e) { setStatus(e.message, 'err'); }
    };
    td3.appendChild(del);
    tr.append(td1, td2, td3);
    frag.appendChild(tr);
  }
  tbody.replaceChildren(frag);
}

// --- auth: single in-page form ---
$('login-btn').onclick = async () => {
  const pw = $('pw').value;
  if (!pw) return;
  try {
    const res = await fetch('/api/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw }),
    });
    if (res.status === 503) { showUnconfigured(); return; }
    if (!res.ok) { setStatus('Incorrect password', 'err'); return; }
    $('pw').value = '';
    showApp();
  } catch { setStatus('Login failed', 'err'); }
};
$('pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('login-btn').click(); });
$('logout').onclick = () => {
  document.cookie = 'dns_dash_session=; Path=/; Max-Age=0';
  showLogin();
};

// --- tabs ---
document.querySelectorAll('.tab').forEach((t) => {
  t.onclick = () => {
    document.querySelectorAll('.tab').forEach((x) => x.classList.toggle('active', x === t));
    document.querySelectorAll('.tab-panel').forEach((p) =>
      p.classList.toggle('hidden', p.id !== 'tab-' + t.dataset.tab));
  };
});

// --- add ---
$('add').onclick = async () => {
  const domain = $('domain').value.trim();
  if (!domain) return;
  try {
    await api('/api/rules', { method: 'POST', body: JSON.stringify({ domain, kind: $('kind').value }) });
    $('domain').value = '';
    setStatus('Added ' + domain, 'ok');
    loadRules();
  } catch (e) { setStatus(e.message, 'err'); }
};
$('domain').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('add').click(); });

// --- bulk ---
$('bulk-add').onclick = async () => {
  const domains = $('bulk-domains').value;
  if (!domains.trim()) return;
  try {
    const r = await api('/api/rules/bulk', {
      method: 'POST',
      body: JSON.stringify({ domains, kind: $('bulk-kind').value }),
    });
    setStatus('Imported ' + r.added + ' rule(s)' + (r.skipped.length ? ', skipped ' + r.skipped.length : ''), 'ok');
    $('bulk-domains').value = '';
    loadRules();
  } catch (e) { setStatus(e.message, 'err'); }
};

// --- test ---
$('test-btn').onclick = () => {
  const domain = $('test-domain').value.trim().toLowerCase();
  if (!domain) return;
  const el = $('test-result');

  const map = new Map(RULES.map((r) => [r.domain, r.kind]));
  if (map.size === 0) { el.textContent = 'No rules loaded.'; return; }

  let d = domain.replace(/\\.$/, '');
  let denyHit = null;
  let result = null;
  for (;;) {
    const hit = map.get(d);
    if (hit === 'allow') { result = { kind: 'allow', at: d }; break; }
    if (hit === 'deny' && denyHit === null) denyHit = { at: d };
    const dot = d.indexOf('.');
    if (dot === -1) break;
    d = d.slice(dot + 1);
    if (d.indexOf('.') === -1) {
      const last = map.get(d);
      if (last === 'allow') { result = { kind: 'allow', at: d }; break; }
      if (last === 'deny' && denyHit === null) denyHit = { at: d };
      break;
    }
  }
  if (!result && denyHit) result = { kind: 'deny', at: denyHit.at };

  if (result) {
    el.innerHTML = '<span class="pill ' + (result.kind === 'allow' ? 'allowed' : 'blocked') + '">' +
      (result.kind === 'allow' ? 'ALLOWED' : 'BLOCKED') + '</span> by rule <code>' + result.at + '</code>';
  } else {
    el.textContent = 'No custom rule matches — falls through to the remote blocklist.';
  }
};

$('filter').oninput = render;

// --- bootstrap: probe auth state without triggering a browser dialog ---
(async () => {
  try {
    const res = await fetch('/api/rules', { credentials: 'same-origin' });
    if (res.ok) showApp();
    else if (res.status === 503) showUnconfigured();
    else showLogin();
  } catch { showLogin(); }
})();
</script>
</body>
</html>`;
