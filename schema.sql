CREATE TABLE IF NOT EXISTS dns_logs (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT    NOT NULL,            -- requested QNAME (lowercased)
  status TEXT    NOT NULL,            -- allow | deny | blocklist | none
  filter TEXT    NOT NULL,            -- allowlist | denylist | blocklist | upstream
  ts     INTEGER NOT NULL             -- unix epoch milliseconds
);

CREATE INDEX IF NOT EXISTS idx_dns_logs_domain ON dns_logs(domain);
CREATE INDEX IF NOT EXISTS idx_dns_logs_status ON dns_logs(status);
CREATE INDEX IF NOT EXISTS idx_dns_logs_ts     ON dns_logs(ts);
