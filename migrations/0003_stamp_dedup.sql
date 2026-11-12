-- Same-digest stamp cooldown (POST /api/stamp and POST /api/mcp/stamp).
-- Stores only the SHA-256 digest, the time of the last successful upstream
-- stamp, and the base64 calendar/TSA payloads already returned to the client.
-- Never stores file bytes or raw IP addresses.
-- Apply to an existing D1 database with:
--   wrangler d1 migrations apply lightdrawer-ct --remote
-- or: wrangler d1 execute lightdrawer-ct --remote --file=migrations/0003_stamp_dedup.sql
-- New installs that apply schema/ct.sql already get this table.

CREATE TABLE IF NOT EXISTS stamp_dedup (
  digest TEXT PRIMARY KEY,
  last_ok_at INTEGER NOT NULL,
  ots_json TEXT NOT NULL,
  tsr TEXT
);

CREATE INDEX IF NOT EXISTS idx_stamp_dedup_last_ok ON stamp_dedup (last_ok_at);
