// Open MCP stamp lane helpers: kill switch, hashed-IP quotas, and prune.
// Raw IP addresses are never written to D1. Counters use HMAC-SHA256(IP + UTC day).

// Designed caps when the vars are unset. A public open lane should set these
// in config (or a smaller number). An explicit 0 turns that one cap off.
export const MCP_LANE_DEFAULT_IP_HOUR = 20;
export const MCP_LANE_DEFAULT_GLOBAL_DAY = 500;
export const MCP_META_KEY = 'mcp_lane';
export const MCP_SALT_DOMAIN = 'lightdrawer-mcp-ip-v1';
// Used only when neither MCP_IP_SALT nor CT_TICK_SECRET is set (local tests / wrangler dev).
const LOCAL_DEV_SALT = 'lightdrawer-mcp-ip-local-dev';

export function mcpLaneEnabledByEnv(env) {
  return String((env && env.MCP_LANE) || '').trim().toLowerCase() === 'on';
}

// 0 means that cap is off (unlimited). Missing or invalid values use the fallback.
export function parseLimitInt(value, fallback) {
  if (value == null || String(value).trim() === '') return fallback;
  const n = Number.parseInt(String(value).trim(), 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

export function mcpLaneLimits(env) {
  return {
    ipHour: parseLimitInt(env && env.MCP_LIMIT_IP_HOUR, MCP_LANE_DEFAULT_IP_HOUR),
    globalDay: parseLimitInt(env && env.MCP_LIMIT_GLOBAL_DAY, MCP_LANE_DEFAULT_GLOBAL_DAY),
  };
}

export function utcDayString(now = new Date()) {
  return now.toISOString().slice(0, 10);
}

export function utcHourString(now = new Date()) {
  return now.toISOString().slice(0, 13);
}

export function secondsUntilNextUtcHour(now = new Date()) {
  const next = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours() + 1);
  return Math.max(1, Math.ceil((next - now.getTime()) / 1000));
}

export function secondsUntilNextUtcDay(now = new Date()) {
  const next = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - now.getTime()) / 1000));
}

function hexFromBuf(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(String(secret)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(String(message)));
  return hexFromBuf(sig);
}

// Prefer MCP_IP_SALT. If it is not set, derive a domain-separated key from
// CT_TICK_SECRET so production needs no extra secret. Local/dev with neither
// uses a fixed string so tests can run without secrets.
export async function resolveMcpIpSalt(env) {
  if (env && env.MCP_IP_SALT) return String(env.MCP_IP_SALT);
  if (env && env.CT_TICK_SECRET) return hmacSha256Hex(env.CT_TICK_SECRET, MCP_SALT_DOMAIN);
  return LOCAL_DEV_SALT;
}

export async function hashMcpIp(env, ip, now = new Date()) {
  const salt = await resolveMcpIpSalt(env);
  return hmacSha256Hex(salt, `v1|${utcDayString(now)}|${ip}`);
}

export async function mcpLaneGate(env) {
  if (!mcpLaneEnabledByEnv(env)) return { allow: false, status: 404 };
  if (!env || !env.CT_DB) return { allow: false, status: 503 };
  try {
    const row = await env.CT_DB.prepare('SELECT value FROM ct_meta WHERE key = ?').bind(MCP_META_KEY).first();
    if (row && String(row.value || '').trim().toLowerCase() === 'off') return { allow: false, status: 404 };
    return { allow: true };
  } catch {
    return { allow: false, status: 503 };
  }
}

export async function consumeMcpLaneQuota(env, ip, now = new Date()) {
  const limits = mcpLaneLimits(env);
  // When both caps are off, do not write any counter rows (no hashed-IP data).
  if (limits.ipHour === 0 && limits.globalDay === 0) {
    return { limited: false, skipped: true };
  }
  try {
    let ipId = null;
    let ipCount = 0;
    if (limits.ipHour > 0) {
      ipId = await hashMcpIp(env, ip, now);
      const hour = utcHourString(now);
      const ipRow = await env.CT_DB.prepare(
        `INSERT INTO mcp_lane_usage (key_kind, key_id, bucket, count)
         VALUES ('ip', ?, ?, 1)
         ON CONFLICT(key_kind, key_id, bucket) DO UPDATE SET count = count + 1
         RETURNING count`,
      ).bind(ipId, hour).first();
      ipCount = Number(ipRow && ipRow.count) || 0;
      if (ipCount > limits.ipHour) {
        return { limited: true, scope: 'ip', retryAfter: secondsUntilNextUtcHour(now), ipId };
      }
    }
    let globalCount = 0;
    if (limits.globalDay > 0) {
      const day = utcDayString(now);
      const globalRow = await env.CT_DB.prepare(
        `INSERT INTO mcp_lane_usage (key_kind, key_id, bucket, count)
         VALUES ('global', 'all', ?, 1)
         ON CONFLICT(key_kind, key_id, bucket) DO UPDATE SET count = count + 1
         RETURNING count`,
      ).bind(day).first();
      globalCount = Number(globalRow && globalRow.count) || 0;
      if (globalCount > limits.globalDay) {
        return { limited: true, scope: 'global', retryAfter: secondsUntilNextUtcDay(now), ipId };
      }
    }
    return { limited: false, ipId, ipCount, globalCount };
  } catch {
    return { unavailable: true };
  }
}

export const MCP_ALARM_429_DEFAULT_PER_MIN = 20;

// In-isolate count of open-lane HTTP 429s for the current UTC minute.
// Not written to D1. Each Worker isolate has its own count, so this is a
// hint, not an account-wide total. Raw IPs are never stored here.
let mcp429Alarm = { minute: '', count: 0, warned: false };

export function resetMcp429AlarmForTests() {
  mcp429Alarm = { minute: '', count: 0, warned: false };
}

export function mcp429AlarmSnapshot() {
  return { minute: mcp429Alarm.minute, count: mcp429Alarm.count, warned: mcp429Alarm.warned };
}

// 0 disables the warning. Missing or invalid values use the default (20).
export function mcpAlarm429PerMin(env) {
  return parseLimitInt(env && env.MCP_ALARM_429_PER_MIN, MCP_ALARM_429_DEFAULT_PER_MIN);
}

export function utcMinuteString(now = new Date()) {
  return now.toISOString().slice(0, 16);
}

// Count one MCP-lane 429. When the count goes above the threshold, emit one
// warning for this UTC minute and do not emit it again until the minute changes.
export function recordMcp429(env, now = new Date()) {
  const threshold = mcpAlarm429PerMin(env);
  if (threshold === 0) return { count: 0, warned: false, disabled: true };
  const minute = utcMinuteString(now);
  if (mcp429Alarm.minute !== minute) {
    mcp429Alarm = { minute, count: 0, warned: false };
  }
  mcp429Alarm.count += 1;
  if (mcp429Alarm.count > threshold && !mcp429Alarm.warned) {
    mcp429Alarm.warned = true;
    console.warn(JSON.stringify({
      msg: 'mcp-lane-alarm',
      reason: '429-spike',
      count: mcp429Alarm.count,
    }));
    return { count: mcp429Alarm.count, warned: true, disabled: false };
  }
  return { count: mcp429Alarm.count, warned: false, disabled: false };
}

export async function pruneMcpLaneUsage(env, now = new Date()) {
  if (!env || !env.CT_DB) return { pruned: false };
  const hour = utcHourString(now);
  const day = utcDayString(now);
  try {
    await env.CT_DB.prepare(
      `DELETE FROM mcp_lane_usage
        WHERE (key_kind = 'ip' AND bucket < ?)
           OR (key_kind = 'global' AND bucket < ?)`,
    ).bind(hour, day).run();
    return { pruned: true, hour, day };
  } catch (e) {
    console.error(JSON.stringify({ msg: 'mcp lane prune error', error: String(e && e.message ? e.message : e) }));
    return { pruned: false };
  }
}
