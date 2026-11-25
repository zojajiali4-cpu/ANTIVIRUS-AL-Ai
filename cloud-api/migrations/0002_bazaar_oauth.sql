CREATE TABLE IF NOT EXISTS bazaar_oauth_states (
  state_hash TEXT PRIMARY KEY CHECK(length(state_hash)=64),
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bazaar_oauth_states_expiry
  ON bazaar_oauth_states(expires_at);

CREATE TABLE IF NOT EXISTS bazaar_oauth_tokens (
  id INTEGER PRIMARY KEY CHECK(id=1),
  iv TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
