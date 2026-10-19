// The worker's own normalizers, re-exported for the dashboard. Both modules are
// plain ES modules with no worker-only APIs, so the browser bundle uses the
// exact same rules the API validates with — no second opinion to drift.
export { normalizeDomain } from '../../rules.js';
export { normalizeTld, normalizeKeyword } from '../../lists.js';
