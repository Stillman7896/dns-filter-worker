const COMMON = /** @type {Record<number, string>} */ ({
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  43: 'DS',
  46: 'RRSIG',
  47: 'NSEC',
  48: 'DNSKEY',
  50: 'NSEC3',
  51: 'NSEC3PARAM',
  52: 'TLSA',
  64: 'SVCB',
  65: 'HTTPS',
});

/** Render a wire qtype number as its common mnemonic, or 'other'. */
/** @param {number|string|null|undefined} qtype @returns {string} */
export function qtypeLabel(qtype) {
  if (qtype === null || qtype === undefined || qtype === '') return '—';
  const n = Number(qtype);
  if (!Number.isInteger(n) || n <= 0) return 'other';
  return COMMON[n] || 'other';
}