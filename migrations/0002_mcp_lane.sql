-- Rate-limit counters for the open MCP stamp lane (POST /api/mcp/stamp).
-- Stores no raw IP addresses: key_id for per-address rows is HMAC-SHA256 of
-- the IP and the UTC day. Rows live only for the current hour (per-address)
-- or current UTC day (global) and are deleted by the 15-minute cron.
-- Apply to an existing D1 database with:
--   wrangler d1 migrations apply lightdrawer-ct --remote
-- or: wrangler d1 execute lightdrawer-ct --remote --file=migrations/0002_mcp_lane.sql
-- New installs that apply schema/ct.sql already get this table.

CREATE TABLE IF NOT EXISTS mcp_lane_usage (
  key_kind TEXT NOT NULL,
  key_id TEXT NOT NULL,
  bucket TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key_kind, key_id, bucket)
);
