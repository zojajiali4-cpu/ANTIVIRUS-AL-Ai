CREATE TABLE IF NOT EXISTS play_billing_verifications (
  purchase_token_sha256 TEXT PRIMARY KEY CHECK(length(purchase_token_sha256)=64),
  product_id TEXT NOT NULL,
  base_plan_id TEXT NOT NULL,
  subscription_state TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  is_trial INTEGER NOT NULL CHECK(is_trial IN (0,1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_play_billing_expiry ON play_billing_verifications(expires_at);

CREATE TABLE IF NOT EXISTS bazaar_billing_verifications (
  purchase_token_sha256 TEXT PRIMARY KEY CHECK(length(purchase_token_sha256)=64),
  product_id TEXT NOT NULL,
  base_plan_id TEXT NOT NULL CHECK(base_plan_id IN ('monthly','annual')),
  subscription_state TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  auto_renewing INTEGER NOT NULL CHECK(auto_renewing IN (0,1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bazaar_billing_expiry ON bazaar_billing_verifications(expires_at);
