// Ambient duck types shared between Workers runtime code and node:test fakes.
// KVLike/D1Like are deliberately narrower than the real bindings so both the
// production bindings and the FakeKV/FakeD1 test doubles satisfy them.

interface KVListPage {
  keys: { name: string }[];
  list_complete: boolean | undefined;
  cursor: string | null | undefined;
}

interface KVLike {
  get(key: string, type?: 'text' | 'json'): Promise<any>;
  put(key: string, value: string): Promise<unknown>;
  delete(key: string): Promise<unknown>;
  list(opts?: { prefix?: string; cursor?: string }): Promise<KVListResultLike>;
}

interface KVListResultLike {
  keys: Array<{ name: string }>;
  list_complete: boolean | undefined;
  cursor: string | null | undefined;
}

interface D1Exec {
  run(): Promise<unknown>;
  first<T = any>(): Promise<T>;
  all(): Promise<{ results: any[] }>;
}

interface D1Statement extends D1Exec {
  bind(...values: unknown[]): D1Exec;
}

interface D1Like {
  prepare(sql: string): D1Statement;
}

/** Workers execution context (subset; sufficient for ctx.waitUntil). */
interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

/** Worker env bindings + vars (a superset; bindings may be absent). */
interface Env {
  RULES?: KVLike | null;
  ASSETS?: { fetch(request: Request): Promise<Response> };
  LOGS?: D1Like;
  BLOCKLIST_URL?: string;
  UPSTREAM_URL?: string;
  /** Optional fallback DoH server used when the primary fails (see upstream.js). */
  UPSTREAM_FALLBACK_URL?: string;
  DASHBOARD_PASSWORD?: string;
}

/** Persistent filter settings blob (stored as settings:main KV JSON). */
interface FilterSettings {
  rebindProtection: boolean;
  idnBlock: boolean;
  tldBlock: boolean;
  keywordBlock: boolean;
  regexBlock: boolean;
  logPassed: boolean;
  logRetentionDays: number;
  /** Provider id from upstream.js; '' = deployment variable, else built-in default. */
  upstreamPreset: string;
  /** DoH URL used by the 'custom' provider. */
  upstreamUrl: string;
  /** Relay URI template used by an ODoH provider. */
  upstreamRelay: string;
  /** Retry a fallback DoH server when the primary fails (timeout, HTTP error, SERVFAIL/REFUSED). */
  upstreamFailover: boolean;
  /** Custom fallback DoH URL; '' uses a built-in alternate provider. */
  upstreamFallbackUrl: string;
}

/** One response route: a fixed answer for a domain and its subdomains. */
interface RouteRule {
  domain: string;
  type: 'a' | 'aaaa' | 'cname';
  value: string;
  ttl: number;
}

/** Everything the dashboard API handlers need, built by worker.js fetch(). */
interface ApiCtx {
  rules: import('./rules.js').RuleStore;
  settings: import('./settings.js').SettingsStore;
  routes: import('./routing.js').RouteStore;
  keywords: import('./lists.js').TextSetStore;
  tlds: import('./lists.js').TextSetStore;
  regex: import('./lists.js').TextSetStore;
  blocklist?: import('./blocklist.js').Blocklist;

  testFn(domain: string, env?: Env): any;
}

/** WebCrypto — present in Workers and in Node >= 20 (X25519 included). */
declare var crypto: Crypto;

// Test doubles poke these onto globalThis (see test/worker.test.js).
declare var caches: any;
declare var __answers: Array<{ type: number; rdata: number[]; ttl?: number }> | undefined;
