const KEY = 'dns-dash-probes';
const MAX = 10;

/** @param {any} e @returns {boolean} */
function valid(e) {
  return Boolean(e) && typeof e.domain === 'string' && typeof e.status === 'string';
}

export function loadProbeHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem(KEY) || '[]');
    return Array.isArray(parsed) ? parsed.filter(valid).slice(0, MAX) : [];
  } catch {
    return [];
  }
}

/** @param {any[]} entries */
function persist(entries) {
  try {
    localStorage.setItem(KEY, JSON.stringify(entries.slice(0, MAX)));
  } catch { /* private mode */ }
}

/** Prepend a result, dedupe by domain, keep the cap, write through. */
/** @param {any[]} entries @param {any} result @returns {any[]} */
export function rememberProbe(entries, result) {
  const entry = { ...result, ts: Date.now() };
  const next = [entry, ...entries.filter((e) => e.domain !== entry.domain)].slice(0, MAX);
  persist(next);
  return next;
}

export function clearProbeHistory() {
  try { localStorage.removeItem(KEY); } catch { /* private mode */ }
}