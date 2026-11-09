-- LightDrawer certificate-log stamp queue (D1).
-- Stores only SHA-256 fingerprints, batch Merkle data, and issued certificate PEMs.
-- Never stores file bytes.

CREATE TABLE IF NOT EXISTS ct_pending (
  digest TEXT PRIMARY KEY,
  received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ct_batches (
  id TEXT PRIMARY KEY,
  opened_at TEXT NOT NULL,
  closed_at TEXT NOT NULL,
  root TEXT NOT NULL,
  tree_size INTEGER NOT NULL,
  leaves_json TEXT NOT NULL,
  proofs_json TEXT NOT NULL,
  hostname TEXT NOT NULL,
  published INTEGER NOT NULL DEFAULT 0,
  cert_id TEXT
);

CREATE TABLE IF NOT EXISTS ct_leaves (
  digest TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ct_certs (
  id TEXT PRIMARY KEY,
  issued_at TEXT NOT NULL,
  hostnames_json TEXT,
  certificate_pem TEXT NOT NULL,
  chain_pems_json TEXT NOT NULL DEFAULT '[]',
  scts_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS ct_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ct_batches_published ON ct_batches (published, id);
CREATE INDEX IF NOT EXISTS idx_ct_leaves_batch ON ct_leaves (batch_id);

-- Trusted-caller stamp keys (hashes only; see migrations/0001_stamp_keys.sql).
CREATE TABLE IF NOT EXISTS stamp_keys (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_stamp_keys_hash ON stamp_keys (key_hash);
