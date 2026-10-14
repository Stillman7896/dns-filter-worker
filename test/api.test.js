// test/api.test.js — /api routes: session auth, rules, settings, filter lists.
// Uses real Request/Response (Node >= 18) against handleApi with FakeKV stores.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleApi } from '../dashboard.js';
import { RuleStore } from '../rules.js';
import { TextSetStore } from '../lists.js';
import { SettingsStore } from '../settings.js';
import { FakeKV } from './helpers.js';

function mkCtx(kv) {
  return {
    rules: new RuleStore(kv),
    settings: new SettingsStore(kv),
    keywords: new TextSetStore(kv, 'keywords:data'),
    tlds: new TextSetStore(kv, 'tlds:data'),
    testFn: async (domain) => ({ domain, status: 'none', filter: 'upstream', matched: null }),
  };
}

const PASSWORD = 'hunter2';

function call(ctx, env, path, { method = 'GET', body, cookie } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (cookie) headers.Cookie = cookie;
  const req = new Request('https://worker.test' + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return handleApi(req, env, new URL(req.url), ctx);
}

function cookieFrom(res) {
  const sc = res.headers.get('set-cookie');
  assert.ok(sc, 'session cookie set');
  return sc.split(';')[0];
}

// ---- session ------------------------------------------------------------------

test('session: unconfigured password -> 503 everywhere', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = {};
  const login = await call(ctx, env, '/api/session', { method: 'POST', body: { password: 'x' } });
  assert.equal(login.status, 503);
  const rules = await call(ctx, env, '/api/rules');
  assert.equal(rules.status, 503);
  assert.equal((await rules.json()).code, 'unconfigured');
});

test('session: wrong password 401, right password sets cookie', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };

  const bad = await call(ctx, env, '/api/session', { method: 'POST', body: { password: 'nope' } });
  assert.equal(bad.status, 401);

  const ok = await call(ctx, env, '/api/session', { method: 'POST', body: { password: PASSWORD } });
  assert.equal(ok.status, 200);

  const bearer = await call(ctx, env, '/api/session', {
    method: 'POST',
    // no JSON body — bearer path
  });
  assert.equal(bearer.status, 401, 'no auth header and no body -> 401');
});

test('auth: cookie grants access, missing cookie -> 401 without WWW-Authenticate', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const login = await call(ctx, env, '/api/session', { method: 'POST', body: { password: PASSWORD } });
  const cookie = cookieFrom(login);

  const ok = await call(ctx, env, '/api/rules', { cookie });
  assert.equal(ok.status, 200);

  const anon = await call(ctx, env, '/api/rules');
  assert.equal(anon.status, 401);
  assert.equal(anon.headers.get('www-authenticate'), null,
    'must NOT send WWW-Authenticate (no browser dialog)');

  const wrongCookie = await call(ctx, env, '/api/rules', { cookie: 'dns_dash_session=wrong' });
  assert.equal(wrongCookie.status, 401);
});

// ---- rules --------------------------------------------------------------------

test('rules: add/get/delete with validation', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const login = await call(ctx, env, '/api/session', { method: 'POST', body: { password: PASSWORD } });
  const cookie = cookieFrom(login);

  const added = await call(ctx, env, '/api/rules', {
    method: 'POST', cookie, body: { domain: 'Evil.Example.COM', kind: 'deny' },
  });
  assert.equal(added.status, 200);
  assert.equal((await added.json()).domain, 'evil.example.com', 'normalized');

  const badDomain = await call(ctx, env, '/api/rules', {
    method: 'POST', cookie, body: { domain: 'nodots', kind: 'deny' },
  });
  assert.equal(badDomain.status, 400);

  const badKind = await call(ctx, env, '/api/rules', {
    method: 'POST', cookie, body: { domain: 'ok.com', kind: 'maybe' },
  });
  assert.equal(badKind.status, 400);

  const listed = await call(ctx, env, '/api/rules', { cookie });
  assert.deepEqual((await listed.json()).rules, [{ domain: 'evil.example.com', kind: 'deny' }]);

  const del = await call(ctx, env, '/api/rules?domain=evil.example.com', { method: 'DELETE', cookie });
  assert.equal((await del.json()).existed, true);

  const listed2 = await call(ctx, env, '/api/rules', { cookie });
  assert.deepEqual((await listed2.json()).rules, []);
});

test('rules: bulk import reports applied and skipped', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const res = await call(ctx, env, '/api/rules/bulk', {
    method: 'POST', cookie,
    body: { kind: 'deny', domains: 'a.com\nb.com\n\nnot valid!!' },
  });
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.added, 2);
  assert.deepEqual(j.skipped, ['not valid!!']);
});

test('rules: unknown route -> 404 (not swallowed by logs guard)', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));
  const res = await call(ctx, env, '/api/nope', { cookie });
  assert.equal(res.status, 404);
});

// ---- test endpoint -------------------------------------------------------------

test('test endpoint: delegates to injected pipeline', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));
  const res = await call(ctx, env, '/api/test?domain=example.com', { cookie });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), {
    domain: 'example.com', status: 'none', filter: 'upstream', matched: null,
  });

  const bad = await call(ctx, env, '/api/test?domain=nodots', { cookie });
  assert.equal(bad.status, 400);
});

// ---- settings -----------------------------------------------------------------

test('settings: GET defaults, POST patch incl. retention validation', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const get = await call(ctx, env, '/api/settings', { cookie });
  const s0 = (await get.json()).settings;
  assert.equal(s0.rebindProtection, true);
  assert.equal(s0.idnBlock, false);
  assert.equal(s0.logRetentionDays, 30);

  const post = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { idnBlock: true, logRetentionDays: 7 },
  });
  const s1 = (await post.json()).settings;
  assert.equal(s1.idnBlock, true);
  assert.equal(s1.logRetentionDays, 7);

  const clamped = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { logRetentionDays: 99999 },
  });
  assert.equal((await clamped.json()).settings.logRetentionDays, 3650);

  const badType = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { logRetentionDays: 'soon' },
  });
  assert.equal(badType.status, 400);

  const noValid = await call(ctx, env, '/api/settings', {
    method: 'POST', cookie, body: { flurb: 1 },
  });
  assert.equal(noValid.status, 400);
});

// ---- filter lists --------------------------------------------------------------

test('filters: tlds + keywords CRUD with validation', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));

  const add = await call(ctx, env, '/api/filters/tlds', {
    method: 'POST', cookie, body: { value: '.ZIP' },
  });
  assert.equal(add.status, 200);
  assert.deepEqual((await add.json()).items, ['zip']);

  const dup = await call(ctx, env, '/api/filters/tlds', {
    method: 'POST', cookie, body: { value: 'zip' },
  });
  assert.equal((await dup.json()).added, false);

  const invalid = await call(ctx, env, '/api/filters/tlds', {
    method: 'POST', cookie, body: { value: 'co.uk' },
  });
  assert.equal(invalid.status, 400);

  const kw = await call(ctx, env, '/api/filters/keywords', {
    method: 'POST', cookie, body: { value: 'DoubleClick' },
  });
  assert.deepEqual((await kw.json()).items, ['doubleclick']);

  const rm = await call(ctx, env, '/api/filters/tlds?value=zip', { method: 'DELETE', cookie });
  assert.equal((await rm.json()).removed, true);
  assert.deepEqual((await (await call(ctx, env, '/api/filters/tlds', { cookie })).json()).items, []);
});

// ---- logs without D1 ------------------------------------------------------------

test('logs: missing D1 binding -> 501 (not 503, not 404)', async () => {
  const kv = new FakeKV();
  const ctx = mkCtx(kv);
  const env = { DASHBOARD_PASSWORD: PASSWORD };
  const cookie = cookieFrom(await call(ctx, env, '/api/session', {
    method: 'POST', body: { password: PASSWORD },
  }));
  const res = await call(ctx, env, '/api/logs', { cookie });
  assert.equal(res.status, 501);
  assert.equal((await res.json()).code, 'no_d1');
});
