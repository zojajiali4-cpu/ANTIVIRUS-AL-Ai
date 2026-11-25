CREATE TABLE IF NOT EXISTS bazaar_subscription_verifications (
  purchase_token_sha256 TEXT PRIMARY KEY CHECK(length(purchase_token_sha256)=64),
  subscription_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bazaar_subscription_expiry
  ON bazaar_subscription_verifications(expires_at);
