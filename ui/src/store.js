// Single app store: boot/session, routed views, data, and the operation +
// notification system every button reports through.
import { reactive, computed } from 'vue';
import { api, ApiError } from './api.js';

export const VIEWS = [
  { id: 'overview', label: 'Overview', verb: 'See traffic', group: 'traffic' },
  { id: 'rules', label: 'Rules', verb: 'Add allow or deny rules', group: 'traffic' },
  { id: 'probe', label: 'Probe', verb: 'Test one domain', group: 'traffic' },
  { id: 'logs', label: 'Logs', verb: 'Read the query log', group: 'traffic' },
  { id: 'lists', label: 'Filter lists', verb: 'Manage blocked TLDs and keywords', group: 'config' },
  { id: 'settings', label: 'Settings', verb: 'Change resolver, routes and logging', group: 'config' },
  { id: 'backup', label: 'Backup', verb: 'Export or import configuration', group: 'config' },
];

export const state = reactive({
  phase: 'boot', // boot | unconfigured | auth | ready
  bootError: null,
  signingOut: false,
  route: 'overview',

  rules: [],
  ruleFilter: '',
  routes: [],
  keywords: [],
  tlds: [],
  settings: null,
  upstream: null,
  upstreamPresets: [],

  logs: { rows: [], total: 0, search: '', status: '', client: '', limit: 50, offset: 0 },
  stats: null,
  statsError: null,

  ops: {},
  flashes: {},
  toasts: [],
  lastId: 1,
});

export const pendingCount = computed(() => Object.keys(state.ops).length);

// ---- routing (hash so a refresh keeps the open view) ----
export function setRoute(id) {
  if (!VIEWS.some((v) => v.id === id)) id = 'overview';
  if (state.route !== id) location.hash = `#/${id}`;
}

function syncHash() {
  const id = (location.hash || '').replace(/^#\/?/, '') || 'overview';
  if (VIEWS.some((v) => v.id === id)) state.route = id;
  else location.replace('#/overview');
}

// ---- notifications ----
// Timers follow the toast's current ttl (pending -> saved can set it later).
const dismissTimers = new Map();

// Failures fade on their own like successes: long enough to read the reason,
// short enough that a run of dead alerts can't stack up. The close button and
// the progress bar stay, so nothing disappears unannounced.
export const ERROR_TTL = 10_000;

function armDismissTimer(id, ttl) {
  cancelDismissTimer(id);
  dismissTimers.set(id, setTimeout(() => dismissToast(id), ttl));
}

function cancelDismissTimer(id) {
  clearTimeout(dismissTimers.get(id));
  dismissTimers.delete(id);
}

function touch(id, patch) {
  const i = state.toasts.findIndex((t) => t.id === id);
  if (i < 0) return;
  Object.assign(state.toasts[i], patch);
  if (state.toasts[i].ttl) armDismissTimer(id, state.toasts[i].ttl);
}

export function pushToast({ kind, text, detail, action, ttl }) {
  const id = state.lastId++;
  state.toasts.push({ id, kind, text, detail: detail || null, action: action || null, ttl: ttl || null });
  if (state.toasts.length > 4) {
    const dropped = state.toasts.splice(0, state.toasts.length - 4);
    dropped.forEach((t) => cancelDismissTimer(t.id));
  }
  if (ttl) armDismissTimer(id, ttl);
  return id;
}

/** Failure alert outside runOp (e.g. a file the reader picked). */
export function pushError(text, detail) {
  return pushToast({ kind: 'error', text, detail, ttl: ERROR_TTL });
}

export function dismissToast(id) {
  cancelDismissTimer(id);
  const i = state.toasts.findIndex((t) => t.id === id);
  if (i >= 0) state.toasts.splice(i, 1);
}

// ---- "ing" copy for the pending alert, derived from the button's label ----
export function ing(verb) {
  const [head, ...rest] = verb.split(' ');
  const stem = head.endsWith('e') ? head.slice(0, -1) : head;
  return [stem + 'ing', ...rest].join(' ');
}

/**
 * Run a backend operation with full feedback: disabled button + spinner
 * (busyKey), a sticky alert that moves pending -> saved/failed, a short
 * button flash, and an optional undo supplied from the result.
 * @param {string} key
 * @param {{verb: string, ok: string|((r:any)=>string), undo?: (r:any)=>Promise<any>|any, fn: () => Promise<any>}} spec
 */
export async function runOp(key, spec) {
  const pending = pushToast({ kind: 'pending', text: ing(spec.verb) + '..' });
  state.ops[key] = true;

  let result;
  try {
    result = await spec.fn();
  } catch (err) {
    const e = err instanceof ApiError ? err : new ApiError(String(err && err.message ? err.message : err));
    if (e.status === 401 && state.phase === 'ready') {
      state.phase = 'auth';
      touch(pending, { kind: 'error', text: 'Session expired', detail: 'Sign in to keep working.', ttl: ERROR_TTL });
    } else if (e.status === 503 && e.code === 'unconfigured') {
      state.phase = 'unconfigured';
      touch(pending, { kind: 'error', text: 'No dashboard password set', detail: 'Set DASHBOARD_PASSWORD in the worker, then reload.', ttl: ERROR_TTL });
    } else {
      const detail = e.status === 500 ? `${e.message} — the worker logged the request; try again quietly later.` : e.message;
      touch(pending, {
        kind: 'error',
        text: `${spec.verb} failed`,
        detail,
        action: { label: 'Try again', run: () => runOp(key, spec) },
        ttl: ERROR_TTL,
      });
    }
    state.flash(key, 'fail');
    throw e;
  } finally {
    delete state.ops[key];
  }

  const ok = typeof spec.ok === 'function' ? spec.ok(result) : spec.ok;
  const undo = spec.undo && result !== undefined
    ? {
        label: 'Undo',
        run: async () => {
          const undoToast = pushToast({ kind: 'pending', text: `Reverting ${ok}..`.replace(/\s+$/, '') });
          try {
            await spec.undo(result);
            touch(undoToast, { kind: 'success', text: 'Reverted', ttl: 3500 });
          } catch {
            touch(undoToast, { kind: 'error', text: 'Revert failed', detail: 'The change stayed in place.', ttl: ERROR_TTL });
          }
        },
      }
    : null;
  touch(pending, { kind: 'success', text: ok, action: undo, ttl: undo ? 9000 : 4200 });
  state.flash(key, 'ok', 1700);
  return result;
}

state.flash = function flash(key, kind, ms = 1500) {
  state.flashes[key] = kind;
  setTimeout(() => {
    if (state.flashes[key] === kind) delete state.flashes[key];
  }, ms);
};

// ---- session / data ----
export async function boot() {
  state.phase = 'boot';
  state.bootError = null;
  try {
    // One call doubles as the probe: 503 = unconfigured, 401 = needs sign-in.
    const config = await api.getSettings();
    state.settings = config.settings;
    state.upstream = config.upstream;
    state.upstreamPresets = config.upstreamPresets || [];
    await Promise.all([loadRules(), loadRoutes(), loadLists()]);
    await Promise.all([loadLogs(), loadStats()]);
    state.phase = 'ready';
  } catch (e) {
    if (e.status === 503) state.phase = 'unconfigured';
    else if (e.status === 401) state.phase = 'auth';
    else {
      state.phase = 'boot';
      state.bootError = e.message;
    }
  }
}

export async function login(password) {
  await api.login(password);
  state.signingOut = false;
  await boot();
}

export async function signOut() {
  try { await api.signOut(); } catch { /* cookie already gone */ }
  // Drop every cached payload so a reload can never rehydrate a signed-in view
  // from stale state, and the cleared cookie is the only thing left to trust.
  state.rules = [];
  state.routes = [];
  state.keywords = [];
  state.tlds = [];
  state.settings = null;
  state.upstream = null;
  state.upstreamPresets = [];
  state.stats = null;
  state.statsError = null;
  state.logs = { rows: [], total: 0, search: '', status: '', client: '', limit: state.logs.limit, offset: 0 };
  dismissTimers.forEach((t) => clearTimeout(t));
  dismissTimers.clear();
  state.toasts = [];
  state.ops = {};
  state.flashes = {};
  state.signingOut = true;
  state.phase = 'auth';
}

export async function loadRules() {
  state.rules = (await api.rules()).rules;
}

export async function loadRoutes() {
  state.routes = (await api.routes()).routes;
}

export async function loadLists() {
  const [k, t] = await Promise.all([api.listItems('keywords'), api.listItems('tlds')]);
  state.keywords = k.items;
  state.tlds = t.items;
}

export async function loadLogs() {
  const { search, status, client, limit, offset } = state.logs;
  // 'untagged' is a UI-only pick of the client select meaning `client IS NULL`.
  const data = await api.logs({
    search,
    status,
    client: client && client !== 'untagged' ? client : '',
    untagged: client === 'untagged' ? 1 : '',
    limit,
    offset,
  });
  state.logs.rows = data.logs;
  state.logs.total = data.total;
}

export async function loadStats() {
  state.statsError = null;
  try {
    state.stats = await api.logStats();
  } catch (e) {
    if (e.code === 'no_d1') state.stats = null;
    state.statsError = e.code === 'no_d1' ? 'no_d1' : e.message;
  }
}

export const filteredRules = computed(() => {
  const q = state.ruleFilter.trim().toLowerCase();
  const rows = q ? state.rules.filter((r) => r.domain.includes(q) || r.kind.includes(q)) : state.rules;
  return rows;
});

export const logPages = computed(() => {
  const { total, limit, offset } = state.logs;
  const pages = Math.max(1, Math.ceil(total / limit));
  return { pages, page: Math.floor(offset / limit) + 1 };
});

export function initStore() {
  window.addEventListener('hashchange', syncHash);
  if (location.hash) syncHash();
  else location.replace('#/overview');
  boot();
}