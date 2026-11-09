-- Additive migration for trusted-caller stamp keys.
-- Stores only SHA-256 hashes of API keys (never the plaintext) plus a label
-- used in Worker logs. Apply to an existing D1 database with:
--   wrangler d1 execute lightdrawer-ct --remote --file=migrations/0001_stamp_keys.sql
-- or: wrangler d1 migrations apply lightdrawer-ct --remote
-- New installs that apply schema/ct.sql already get this table.

CREATE TABLE IF NOT EXISTS stamp_keys (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_stamp_keys_hash ON stamp_keys (key_hash);
