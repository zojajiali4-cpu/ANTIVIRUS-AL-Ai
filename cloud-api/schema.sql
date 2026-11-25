CREATE TABLE IF NOT EXISTS hash_reputation (sha256 TEXT PRIMARY KEY CHECK(length(sha256)=64), classification TEXT NOT NULL CHECK(classification IN ('MALWARE','PUA','SUSPICIOUS')), family_id TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'ANTIVIRUS-AL-AI', updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS url_reputation (host TEXT PRIMARY KEY, classification TEXT NOT NULL CHECK(classification IN ('MALICIOUS','PHISHING','SUSPICIOUS','TRUSTED')), source TEXT NOT NULL DEFAULT 'ANTIVIRUS-AL-AI', updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS signed_feeds (version INTEGER PRIMARY KEY, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_rate_limits (ip_hash TEXT NOT NULL, bucket INTEGER NOT NULL, hits INTEGER NOT NULL, PRIMARY KEY(ip_hash,bucket));
CREATE INDEX IF NOT EXISTS idx_hash_classification ON hash_reputation(classification);
CREATE INDEX IF NOT EXISTS idx_url_classification ON url_reputation(classification);
CREATE TABLE IF NOT EXISTS bazaar_subscription_verifications (
  purchase_token_sha256 TEXT PRIMARY KEY CHECK(length(purchase_token_sha256)=64),
  subscription_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bazaar_subscription_expiry ON bazaar_subscription_verifications(expires_at);

CREATE TABLE IF NOT EXISTS bazaar_oauth_states (
  state_hash TEXT PRIMARY KEY CHECK(length(state_hash)=64),
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bazaar_oauth_states_expiry ON bazaar_oauth_states(expires_at);
CREATE TABLE IF NOT EXISTS bazaar_oauth_tokens (
  id INTEGER PRIMARY KEY CHECK(id=1),
  iv TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
