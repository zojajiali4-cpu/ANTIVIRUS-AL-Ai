CREATE TABLE IF NOT EXISTS hash_reputation (sha256 TEXT PRIMARY KEY CHECK(length(sha256)=64), classification TEXT NOT NULL CHECK(classification IN ('MALWARE','PUA','SUSPICIOUS')), family_id TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'ANTIVIRUS-AL-AI', updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS url_reputation (host TEXT PRIMARY KEY, classification TEXT NOT NULL CHECK(classification IN ('MALICIOUS','PHISHING','SUSPICIOUS','TRUSTED')), source TEXT NOT NULL DEFAULT 'ANTIVIRUS-AL-AI', updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS signed_feeds (version INTEGER PRIMARY KEY, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_rate_limits (ip_hash TEXT NOT NULL, bucket INTEGER NOT NULL, hits INTEGER NOT NULL, PRIMARY KEY(ip_hash,bucket));
CREATE INDEX IF NOT EXISTS idx_hash_classification ON hash_reputation(classification);
CREATE INDEX IF NOT EXISTS idx_url_classification ON url_reputation(classification);
CREATE TABLE IF NOT EXISTS play_billing_verifications (
  purchase_token_sha256 TEXT PRIMARY KEY CHECK(length(purchase_token_sha256) = 64),
  product_id TEXT NOT NULL,
  base_plan_id TEXT NOT NULL,
  subscription_state TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  is_trial INTEGER NOT NULL CHECK(is_trial IN (0, 1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_play_billing_expiry
  ON play_billing_verifications(expires_at);
