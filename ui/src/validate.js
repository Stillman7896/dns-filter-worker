// The worker's own normalizers, re-exported for the dashboard. Both modules are
// plain ES modules with no worker-only APIs, so the browser bundle uses the
// exact same rules the API validates with — no second opinion to drift.
export { normalizeDomain } from '../../rules.js';
export { toAscii, toUnicode } from '../../idn.js';
export { normalizeTld, normalizeKeyword, normalizeRegex } from '../../lists.js';
export { normalizeRouteValue } from '../../routing.js';
// Blocklist subscriptions share their limits between the API and the forms.
export { normalizeBlocklistUrls, MAX_BLOCKLIST_URLS, BLOCKLIST_ENTRY_LIMIT } from '../../blocklist.js';

/** Same test the API applies to a custom provider URL.
 * @param {string} value
 * @returns {boolean}
 */
export function isHttpsUrl(value) {
  if (typeof value !== 'string' || !value.trim()) return false;
  try {
    const url = new URL(value.trim());
    return url.protocol === 'https:' && !url.username && !url.password;
  } catch {
    return false;
  }
}

/** Same shape check the API applies to an ODoH relay template.
 * @param {string} value
 * @returns {boolean}
 */
export function isRelayTemplate(value) {
  if (typeof value !== 'string' || !value.startsWith('https://')) return false;
  const vars = value.match(/\{[^}]*\}/g) || [];
  return vars.length === 1 && vars[0] === '{?targethost,targetpath}';
}
