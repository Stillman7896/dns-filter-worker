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

export async function handleApi(request, env, url, rules, testFn, settings) {
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

  // ---- test domain: full server-side pipeline (custom rules + blocklist) ----
  if (path === '/api/test' && request.method === 'GET') {
    const domain = normalizeDomain(url.searchParams.get('domain') || '');
    if (!domain) return json({ error: 'invalid domain' }, { status: 400 });
    if (typeof testFn !== 'function') return json({ error: 'test not available' }, { status: 501 });
    return json(await testFn(domain, env));
  }

  // ---- settings (KV, persistent) ----
  if (path === '/api/settings') {
    if (!settings) return json({ error: 'settings not available' }, { status: 501 });

    if (request.method === 'GET') {
      await settings.refresh(true);
      return json({ settings: settings.get() });
    }

    if (request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'bad json' }, { status: 400 }); }

      const patch = {};
      if (typeof body.rebindProtection === 'boolean') patch.rebindProtection = body.rebindProtection;
      if (typeof body.idnBlock === 'boolean') patch.idnBlock = body.idnBlock;
      if (Object.keys(patch).length === 0) {
        return json({ error: 'no valid settings provided' }, { status: 400 });
      }

      await settings.update(patch);
      return json({ ok: true, settings: settings.get() });
    }
  }

  // ---- logs (D1) ----
  const isLogsPath = path === '/api/logs' || path.startsWith('/api/logs/');
  if (isLogsPath) {
    const logs = env.LOGS;
    if (!logs) {
      // 501 (not 503) so the frontend doesn't mistake this for "password not configured".
      return json({ error: 'D1 logging not configured', code: 'no_d1' }, { status: 501 });
    }

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
  }

  return json({ error: 'not found' }, { status: 404 });
}

