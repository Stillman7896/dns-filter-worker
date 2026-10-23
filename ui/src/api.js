// Typed-ish client for the worker's /api/* routes. Every failure surfaces as an
// ApiError so views can show the server's own wording in a sticky alert.

export class ApiError extends Error {
  constructor(message, status = 0, code = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

/** @param {string} path @param {{method?: string, body?: any, query?: Record<string, any>}} [opts] */
export async function request(path, { method = 'GET', body, query } = {}) {
  const url = new URL(path, window.location.origin);
  for (const [k, v] of Object.entries(query || {})) {
    if (v === '' || v === null || v === undefined) continue;
    url.searchParams.set(k, String(v));
  }

  let res;
  try {
    res = await fetch(url, {
      method,
      credentials: 'same-origin',
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError('no answer from the worker — check the deployment or your connection.', 0, 'network');
  }

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new ApiError(
      (data && data.error) || `request failed (${res.status})`,
      res.status,
      (data && data.code) || null
    );
  }
  // A 200 with an unparsable body (deploy misroute serving index.html) must
  // not surface as null downcall — callers would read properties off it.
  if (data === null) {
    throw new ApiError('worker sent a non-JSON response for ' + path, 0, 'not-json');
  }
  return data;
}

export const api = {
  // session
  login: (password) => request('/api/session', { method: 'POST', body: { password } }),
  signOut: () => request('/api/session', { method: 'DELETE' }),

  // custom rules
  rules: () => request('/api/rules'),
  addRule: (domain, kind) => request('/api/rules', { method: 'POST', body: { domain, kind } }),
  deleteRule: (domain) => request('/api/rules', { method: 'DELETE', query: { domain } }),
  bulkRules: (kind, domains) => request('/api/rules/bulk', { method: 'POST', body: { kind, domains } }),

  // verdict probe
  probe: (domain) => request('/api/test', { query: { domain } }),

  // settings + upstream provider
  getSettings: () => request('/api/settings'),
  saveSettings: (patch) => request('/api/settings', { method: 'POST', body: patch }),
  testUpstream: (candidate) => request('/api/upstream/test', { method: 'POST', body: candidate }),

  // response routes
  routes: () => request('/api/routes'),
  addRoute: (route) => request('/api/routes', { method: 'POST', body: route }),
  deleteRoute: (domain) => request('/api/routes', { method: 'DELETE', query: { domain } }),

  // backup
  exportConfig: () => request('/api/export'),
  importConfig: (payload) => request('/api/import', { method: 'POST', body: payload }),

  // filter lists
  listItems: (kind) => request(`/api/filters/${kind}`),
  addItem: (kind, value) => request(`/api/filters/${kind}`, { method: 'POST', body: { value } }),
  removeItem: (kind, value) => request(`/api/filters/${kind}`, { method: 'DELETE', query: { value } }),

  // blocklist subscriptions
  blocklists: () => request('/api/blocklists'),
  addBlocklist: (url) => request('/api/blocklists', { method: 'POST', body: { url } }),
  removeBlocklist: (url) => request('/api/blocklists', { method: 'DELETE', query: { url } }),
  reloadBlocklists: () => request('/api/blocklists/refresh', { method: 'POST' }),

  // audit log
  logs: (query) => request('/api/logs', { query }),
  deleteLogs: (query) => request('/api/logs', { method: 'DELETE', query }),
  deleteLog: (id) => request(`/api/logs/${id}`, { method: 'DELETE' }),
  logStats: () => request('/api/logs/stats'),
};