// odoh.js — Oblivious DoH client (RFC 9230) on HPKE base mode (RFC 9180).
//
// Suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM — the suite
// RFC 9230 §9 requires. The target's key is read from
// https://<target>/.well-known/odohconfigs and cached per isolate, the query
// is encrypted into an ObliviousDoHMessage, and the relay only ever sees
// ciphertext plus the target hostname.
//
// Everything here is pure crypto + encoding: no I/O besides the optional
// config fetch, so the whole path is unit-testable against RFC test vectors.

const CONFIG_PATH = '/.well-known/odohconfigs';
const CONFIG_TTL_MS = 6 * 60 * 60 * 1000;
const OBLIVIOUS_MEDIA_TYPE = 'application/oblivious-dns-message';

/** See RFC 9230 §9 (and RFC 9180 §7 identifiers). */
export const SUITE = Object.freeze({ kemId: 0x0020, kdfId: 0x0001, aeadId: 0x0001 });

const enc = new TextEncoder();
const N_H = 32; // SHA-256 output
const N_K = 16; // AES-128-GCM key
const N_N = 12; // AES-GCM nonce

// PKCS#8 prefix for an X25519 private key (RFC 8410); WebCrypto's "raw"
// import path is for public keys only.
const PKCS8_X25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);
const X25519_BASE = Uint8Array.from([9, ...new Array(31).fill(0)]);

/** @returns {SubtleCrypto} */
function subtle() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) throw new Error('WebCrypto unavailable');
  return c.subtle;
}

/** @param {number} n @returns {Uint8Array} */
function u16(n) {
  return Uint8Array.of((n >>> 8) & 0xff, n & 0xff);
}

/** @param {Uint8Array[]} parts @returns {Uint8Array} */
export function concat(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** @param {Uint8Array|null|undefined} bytes @returns {string} */
export function toHex(bytes) {
  return bytes ? [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('') : '';
}

/** @param {string} hex @returns {Uint8Array} */
export function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ---- HKDF (RFC 5869) ----

/** @param {Uint8Array} key @returns {Promise<CryptoKey>} */
async function hmacKey(key) {
  return subtle().importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

/** @param {Uint8Array} salt @param {Uint8Array} ikm @returns {Promise<Uint8Array>} */
export async function hkdfExtract(salt, ikm) {
  const key = await hmacKey(salt.length ? salt : new Uint8Array(N_H));
  return new Uint8Array(await subtle().sign('HMAC', key, ikm));
}

/** @param {Uint8Array} prk @param {Uint8Array} info @param {number} length @returns {Promise<Uint8Array>} */
export async function hkdfExpand(prk, info, length) {
  const key = await hmacKey(prk);
  /** @type {Uint8Array} */
  let out = new Uint8Array(0);
  /** @type {Uint8Array} */
  let block = new Uint8Array(0);
  for (let i = 1; out.length < length; i++) {
    block = new Uint8Array(await subtle().sign('HMAC', key, concat([block, info, Uint8Array.of(i)])));
    out = concat([out, block]);
  }
  return out.slice(0, length);
}

// ---- HPKE labeled KDF helpers (RFC 9180 §4) ----

/** @param {number} kemId @param {number} kdfId @param {number} aeadId @returns {Uint8Array} */
function kdfSuiteId(kemId, kdfId, aeadId) {
  return concat([enc.encode('HPKE'), u16(kemId), u16(kdfId), u16(aeadId)]);
}

/** @param {number} kemId @returns {Uint8Array} */
function kemSuiteId(kemId) {
  return concat([enc.encode('KEM'), u16(kemId)]);
}

/** @param {Uint8Array} salt @param {string} label @param {Uint8Array} ikm @param {Uint8Array} suiteId */
async function labeledExtract(salt, label, ikm, suiteId) {
  return hkdfExtract(salt, concat([enc.encode('HPKE-v1'), suiteId, enc.encode(label), ikm]));
}

/** @param {Uint8Array} prk @param {string} label @param {Uint8Array} info @param {number} length @param {Uint8Array} suiteId */
async function labeledExpand(prk, label, info, length, suiteId) {
  return hkdfExpand(
    prk,
    concat([u16(length), enc.encode('HPKE-v1'), suiteId, enc.encode(label), info]),
    length,
  );
}

// ---- X25519 ----

/** @param {Uint8Array} sk @param {Uint8Array} pk @returns {Promise<Uint8Array>} */
export async function x25519(sk, pk) {
  const priv = await subtle().importKey('pkcs8', concat([PKCS8_X25519_PREFIX, sk]), { name: 'X25519' }, false, ['deriveBits']);
  const pub = await subtle().importKey('raw', pk, { name: 'X25519' }, false, []);
  // `public` is the X25519 peer key; the workers-types union spells it $public.
  const params = /** @type {any} */ ({ name: 'X25519', public: pub });
  return new Uint8Array(await subtle().deriveBits(params, priv, 256));
}

/** Public key for a raw 32-byte X25519 secret.
 * @param {Uint8Array} sk @returns {Promise<Uint8Array>}
 */
export function x25519PublicKey(sk) {
  return x25519(sk, X25519_BASE);
}

// ---- HPKE base-mode key schedule (RFC 9180 §5.1) ----

/**
 * Everything the sender needs after encapsulating to the recipient.
 * @typedef {object} HpkeContext
 * @property {Uint8Array} enc encapsulated key
 * @property {Uint8Array} key AEAD key
 * @property {Uint8Array} baseNonce
 * @property {Uint8Array} exporterSecret
 * @property {number} aeadId
 */

/**
 * @param {Uint8Array} sharedSecret
 * @param {Uint8Array} info
 * @param {{kemId: number, kdfId: number, aeadId: number}} suite
 * @returns {Promise<{key: Uint8Array, baseNonce: Uint8Array, exporterSecret: Uint8Array}>}
 */
export async function keySchedule(sharedSecret, info, suite) {
  const suiteId = kdfSuiteId(suite.kemId, suite.kdfId, suite.aeadId);
  const pskIdHash = await labeledExtract(new Uint8Array(0), 'psk_id_hash', new Uint8Array(0), suiteId);
  const infoHash = await labeledExtract(new Uint8Array(0), 'info_hash', info, suiteId);
  const context = concat([Uint8Array.of(0), pskIdHash, infoHash]); // mode_base
  const secret = await labeledExtract(sharedSecret, 'secret', new Uint8Array(0), suiteId);
  return {
    key: await labeledExpand(secret, 'key', context, N_K, suiteId),
    baseNonce: await labeledExpand(secret, 'base_nonce', context, N_N, suiteId),
    exporterSecret: await labeledExpand(secret, 'exp', context, N_H, suiteId),
  };
}

/**
 * DhKEM ExtractAndExpand (RFC 9180 §4.1): DH output + KEM context -> shared secret.
 * @param {Uint8Array} dh @param {Uint8Array} kemContext @param {{kemId:number,kdfId:number,aeadId:number}} suite
 * @returns {Promise<Uint8Array>}
 */
async function extractAndExpand(dh, kemContext, suite) {
  const kemSuite = kemSuiteId(suite.kemId);
  const eaePrk = await labeledExtract(new Uint8Array(0), 'eae_prk', dh, kemSuite);
  return labeledExpand(eaePrk, 'shared_secret', kemContext, N_H, kemSuite);
}

/**
 * SetupBaseS: encapsulate to `pkR` and derive the sender context.
 * @param {Uint8Array} pkR
 * @param {Uint8Array} info
 * @param {Uint8Array} [skE] fixed ephemeral secret (test vectors only)
 * @param {{kemId: number, kdfId: number, aeadId: number}} [suite]
 * @returns {Promise<HpkeContext>}
 */
export async function setupBaseS(pkR, info, skE, suite = SUITE) {
  const sk = skE || globalThis.crypto.getRandomValues(new Uint8Array(32));
  const enc = await x25519PublicKey(sk);
  const dh = await x25519(sk, pkR);
  const sharedSecret = await extractAndExpand(dh, concat([enc, pkR]), suite);
  return { enc, aeadId: suite.aeadId, ...await keySchedule(sharedSecret, info, suite) };
}

/**
 * SetupBaseR — the recipient half of the same exchange. Needed by the ODoH
 * round-trip test and by any target-side code built on this module.
 * @param {Uint8Array} enc @param {Uint8Array} skR @param {Uint8Array} info @param {Uint8Array} pkR
 * @param {{kemId: number, kdfId: number, aeadId: number}} [suite]
 * @returns {Promise<HpkeContext>}
 */
export async function setupBaseR(enc, skR, info, pkR, suite = SUITE) {
  const dh = await x25519(skR, enc);
  const sharedSecret = await extractAndExpand(dh, concat([enc, pkR]), suite);
  return { enc, aeadId: suite.aeadId, ...await keySchedule(sharedSecret, info, suite) };
}

/** @param {Uint8Array} exporterSecret @param {Uint8Array} context @param {number} length @param {{kemId:number,kdfId:number,aeadId:number}} [suite] */
export async function contextExport(exporterSecret, context, length, suite = SUITE) {
  // RFC 9180 §5.3: the export label is "sec", not "exp".
  return labeledExpand(exporterSecret, 'sec', context, length, kdfSuiteId(suite.kemId, suite.kdfId, suite.aeadId));
}

/** @param {Uint8Array} baseNonce @param {number} seq @returns {Uint8Array} */
export function nonceFor(baseNonce, seq) {
  const out = baseNonce.slice();
  for (let i = out.length - 1, s = seq; i >= 0 && s > 0; i--) {
    out[i] ^= s & 0xff;
    s >>>= 8;
  }
  return out;
}

/** @param {Uint8Array} key @param {Uint8Array} nonce @param {Uint8Array} aad @param {Uint8Array} pt @returns {Promise<Uint8Array>} */
export async function aeadSeal(key, nonce, aad, pt) {
  const k = await subtle().importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, k, pt);
  return new Uint8Array(ct);
}

/** @param {Uint8Array} key @param {Uint8Array} nonce @param {Uint8Array} aad @param {Uint8Array} ct @returns {Promise<Uint8Array>} */
export async function aeadOpen(key, nonce, aad, ct) {
  const k = await subtle().importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await subtle().decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, k, ct);
  return new Uint8Array(pt);
}

// ---- ODoH wire format (RFC 9230 §5, §6) ----

/**
 * @typedef {object} OdohConfig
 * @property {number} kemId
 * @property {number} kdfId
 * @property {number} aeadId
 * @property {Uint8Array} publicKey
 * @property {Uint8Array} contents serialized ObliviousDoHConfigContents (the key_id input)
 */

/**
 * First config in an ObliviousDoHConfigs blob this worker can use.
 * @param {Uint8Array} bytes
 * @returns {OdohConfig|null}
 */
export function parseOdohConfigs(bytes) {
  if (!bytes || bytes.length < 6) return null;
  const total = (bytes[0] << 8) | bytes[1];
  const view = bytes.subarray(2, 2 + total);
  let off = 0;
  while (off + 4 <= view.length) {
    const version = (view[off] << 8) | view[off + 1];
    const len = (view[off + 2] << 8) | view[off + 3];
    const start = off + 4;
    const end = start + len;
    if (end > view.length) return null;
    if (version === 0x0001 && len >= 8) {
      const contents = view.subarray(start, end);
      const kemId = (contents[0] << 8) | contents[1];
      const kdfId = (contents[2] << 8) | contents[3];
      const aeadId = (contents[4] << 8) | contents[5];
      const keyLen = (contents[6] << 8) | contents[7];
      if (contents.length >= 8 + keyLen) {
        const supported = kemId === SUITE.kemId && kdfId === SUITE.kdfId && aeadId === SUITE.aeadId;
        if (supported) {
          return { kemId, kdfId, aeadId, publicKey: contents.slice(8, 8 + keyLen), contents: contents.slice() };
        }
      }
    }
    off = end;
  }
  return null;
}

/**
 * key_id = Expand(Extract("", config), "odoh key id", Nh)  (RFC 9230 §6).
 * @param {Uint8Array} contents
 * @returns {Promise<Uint8Array>}
 */
export async function odohKeyId(contents) {
  return hkdfExpand(await hkdfExtract(new Uint8Array(0), contents), enc.encode('odoh key id'), N_H);
}

/** `ObliviousDoHMessagePlaintext { dns_message; padding }`. */
/** @param {Uint8Array} message @returns {Uint8Array} */
export function encodePlaintext(message) {
  return concat([u16(message.length), message, u16(0)]);
}

/** @param {Uint8Array} plain @returns {Uint8Array|null} null when padding is not all zeros */
export function decodePlaintext(plain) {
  if (plain.length < 4) return null;
  const len = (plain[0] << 8) | plain[1];
  if (4 + len > plain.length) return null;
  for (let i = 2 + len; i < plain.length; i++) {
    if (plain[i] !== 0) return null;
  }
  return plain.slice(2, 2 + len);
}

/** @param {number} messageType @param {Uint8Array} keyId @param {Uint8Array} encrypted @returns {Uint8Array} */
export function encodeMessage(messageType, keyId, encrypted) {
  return concat([Uint8Array.of(messageType), u16(keyId.length), keyId, u16(encrypted.length), encrypted]);
}

/** @param {Uint8Array} body @returns {{messageType: number, keyId: Uint8Array, encrypted: Uint8Array}|null} */
export function decodeMessage(body) {
  if (body.length < 5) return null;
  const messageType = body[0];
  const keyLen = (body[1] << 8) | body[2];
  const keyId = body.subarray(3, 3 + keyLen);
  const encOff = 3 + keyLen;
  if (encOff + 2 > body.length) return null;
  const msgLen = (body[encOff] << 8) | body[encOff + 1];
  const encrypted = body.subarray(encOff + 2, encOff + 2 + msgLen);
  if (encrypted.length !== msgLen) return null;
  return { messageType, keyId, encrypted };
}

/** AAD binding a query to its key id (RFC 9230 §6).
 * @param {Uint8Array} keyId @returns {Uint8Array}
 */
export function queryAad(keyId) {
  return concat([Uint8Array.of(0x01), u16(keyId.length), keyId]);
}

/** @param {Uint8Array} respNonce @returns {Uint8Array} */
export function responseAad(respNonce) {
  return concat([Uint8Array.of(0x02), u16(respNonce.length), respNonce]);
}

// ---- Relay URI template (RFC 9230 §4.1, RFC 6570 level 3) ----

const QUERY_TEMPLATE = '{?targethost,targetpath}';

/**
 * Expand a relay template for `host` + `path`, or null when it is not a valid
 * ODoH template (both variables exactly once, no others).
 * @param {string} template
 * @param {string} host
 * @param {string} path
 * @returns {string|null}
 */
export function expandRelayTemplate(template, host, path) {
  if (typeof template !== 'string' || !template.startsWith('https://')) return null;
  const vars = template.match(/\{[^}]*\}/g) || [];
  const bare = vars.filter((v) => v !== QUERY_TEMPLATE);
  if (bare.length) return null;
  if (vars.filter((v) => v === QUERY_TEMPLATE).length > 1) return null;

  const query = `?targethost=${encodeURIComponent(host)}&targetpath=${encodeURIComponent(path)}`;
  if (vars.length === 1 && vars[0] === QUERY_TEMPLATE) {
    return template.replace(QUERY_TEMPLATE, query);
  }
  // No variables at all: a relay that takes the target in the path.
  return null;
}

// ---- Config cache + request preparation ----

/** @type {Map<string, {config: OdohConfig, at: number}>} */
const configCache = new Map();

/** @param {string} targetUrl @param {number} [now] @returns {OdohConfig|null} */
function cachedConfig(targetUrl, now = Date.now()) {
  const hit = configCache.get(targetUrl);
  if (hit && now - hit.at < CONFIG_TTL_MS) return hit.config;
  return null;
}

/**
 * Fetch + parse the target's ODoH key.
 * @param {string} targetUrl
 * @param {typeof fetch} [fetchImpl]
 * @returns {Promise<OdohConfig>}
 */
export async function fetchOdohConfig(targetUrl, fetchImpl = fetch) {
  const origin = new URL(targetUrl).origin;
  const res = await fetchImpl(origin + CONFIG_PATH, { headers: { Accept: 'application/octet-stream' } });
  if (!res.ok) throw new Error(`odoh config HTTP ${res.status}`);
  const config = parseOdohConfigs(new Uint8Array(await res.arrayBuffer()));
  if (!config) throw new Error('odoh config unsupported');
  configCache.set(targetUrl, { config, at: Date.now() });
  return config;
}

/**
 * Build the relay request for one query. Returns the URL, the body, and a
 * `decrypt` closure for the relay's response — the caller does the I/O.
 * @param {string} targetUrl
 * @param {string} relayTemplate
 * @param {Uint8Array} queryBuf
 * @param {{fetchImpl?: typeof fetch, config?: OdohConfig, skE?: Uint8Array}} [opts]
 * @returns {Promise<{url: string, body: Uint8Array, contentType: string, decrypt: (responseBody: Uint8Array) => Promise<Uint8Array>}>}
 */
export async function prepareOdohQuery(targetUrl, relayTemplate, queryBuf, opts = {}) {
  const target = new URL(targetUrl);
  const url = expandRelayTemplate(relayTemplate, target.hostname, target.pathname);
  if (!url) throw new Error('relay must be an https template containing {?targethost,targetpath}');

  const config = opts.config || cachedConfig(targetUrl) || await fetchOdohConfig(targetUrl, opts.fetchImpl || fetch);
  const keyId = await odohKeyId(config.contents);
  const context = await setupBaseS(config.publicKey, enc.encode('odoh query'), opts.skE, {
    kemId: config.kemId, kdfId: config.kdfId, aeadId: config.aeadId,
  });

  const plain = encodePlaintext(queryBuf);
  const sealed = await aeadSeal(context.key, context.baseNonce, queryAad(keyId), plain);
  const body = encodeMessage(0x01, keyId, concat([context.enc, sealed]));

  return {
    url,
    body,
    contentType: OBLIVIOUS_MEDIA_TYPE,
    /** @param {Uint8Array} responseBody */
    decrypt: async (responseBody) => {
      const message = decodeMessage(responseBody);
      if (!message) throw new Error('malformed odoh response');
      if (message.messageType !== 0x02) throw new Error(`unexpected odoh message type ${message.messageType}`);
      const respNonce = message.keyId;
      const exported = await contextExport(context.exporterSecret, enc.encode('odoh response'), N_K, {
        kemId: config.kemId, kdfId: config.kdfId, aeadId: config.aeadId,
      });
      const salt = concat([plain, u16(respNonce.length), respNonce]);
      const prk = await hkdfExtract(salt, exported);
      const key = await hkdfExpand(prk, enc.encode('odoh key'), N_K);
      const nonce = await hkdfExpand(prk, enc.encode('odoh nonce'), N_N);
      const clear = await aeadOpen(key, nonce, responseAad(respNonce), message.encrypted);
      const dns = decodePlaintext(clear);
      if (!dns) throw new Error('odoh response padding invalid');
      return dns;
    },
  };
}

/**
 * Send one query through the relay and return the plaintext DNS response.
 * @param {string} targetUrl @param {string} relayTemplate @param {Uint8Array} queryBuf
 * @param {{fetchImpl?: typeof fetch}} [opts]
 * @returns {Promise<Uint8Array>}
 */
export async function odohForward(targetUrl, relayTemplate, queryBuf, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const prepared = await prepareOdohQuery(targetUrl, relayTemplate, queryBuf, opts);
  const res = await fetchImpl(prepared.url, {
    method: 'POST',
    headers: { 'Content-Type': prepared.contentType, Accept: prepared.contentType },
    body: prepared.body,
  });
  if (!res.ok) throw new Error(`relay HTTP ${res.status}`);
  return prepared.decrypt(new Uint8Array(await res.arrayBuffer()));
}

/** Drop the cached target key (tests / after a config change). */
export function clearConfigCache() {
  configCache.clear();
}
