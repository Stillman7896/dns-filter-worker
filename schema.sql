-- D1 schema for DNS query audit logs
-- Apply with:
--   wrangler d1 execute dns-logs --file=./schema.sql
-- Also auto-created lazily by the worker on first logged query. Existing tables
-- are migrated automatically (the worker runs `ALTER TABLE ... ADD COLUMN
-- qtype/client` once per isolate and ignores the duplicate-column error).

CREATE TABLE IF NOT EXISTS dns_logs (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT    NOT NULL,            -- requested QNAME (lowercased)
  status TEXT    NOT NULL,            -- allow | deny | blocklist | tld | keyword | rebind | idn | none
  filter TEXT    NOT NULL,            -- allowlist | denylist | blocklist | tld | keyword | rebind | idn | upstream
  ts     INTEGER NOT NULL,            -- unix epoch milliseconds
  qtype  INTEGER,                     -- DNS query type (1=A, 28=AAAA, 16=TXT, 65=HTTPS, ...)
  client TEXT                         -- tag from the DoH URL (/dns-query/<tag> or ?tag=), null when untagged
);

CREATE INDEX IF NOT EXISTS idx_dns_logs_domain ON dns_logs(domain);
CREATE INDEX IF NOT EXISTS idx_dns_logs_status ON dns_logs(status);
CREATE INDEX IF NOT EXISTS idx_dns_logs_ts     ON dns_logs(ts);
CREATE INDEX IF NOT EXISTS idx_dns_logs_client ON dns_logs(client);
