import test from 'node:test';
import assert from 'node:assert/strict';

const store = new Map();
globalThis.localStorage = {
  get length() { return store.size; },
  clear: () => store.clear(),
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  key: (i) => Array.from(store.keys())[i] ?? null,
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};

const { loadProbeHistory, rememberProbe, clearProbeHistory } = await import('../ui/src/probeHistory.js');

test('probeHistory: persists recent probes locally, dedupes by domain, caps to 10', () => {
  /** @type {{ domain: string; status: string }[]} */
  const rows = [];
  for (let i = 0; i < 12; i++) {
    rows.push({ domain: `example${i}.test`, status: i % 2 ? 'deny' : 'none' });
  }
  let finalRows = /** @type {any[]} */ ([]);
  for (const row of rows) finalRows = rememberProbe(finalRows, row);
  rememberProbe(finalRows, { domain: 'example11.test', status: 'blocklist' });

  const loaded = loadProbeHistory();
  assert.equal(loaded.length, 10);
  assert.equal(loaded[0].domain, 'example11.test');
  assert.equal(loaded[0].status, 'blocklist');
  assert.equal(loaded.filter((r) => r.domain === 'example11.test').length, 1);
  assert.ok(loaded.every((r) => typeof r.ts === 'number'));

  clearProbeHistory();
  assert.deepEqual(loadProbeHistory(), []);
});

test('probeHistory: malformed local data is ignored', () => {
  const key = 'dns' + '-dash-probes';
  localStorage.setItem(key, '{"not":"an array"}');
  assert.deepEqual(loadProbeHistory(), []);
  localStorage.setItem(key, '[{"domain":1,"status":"none"},{"domain":"ok.test","status":"none"}]');
  assert.deepEqual(loadProbeHistory(), [{ domain: 'ok.test', status: 'none' }]);
  clearProbeHistory();
});