// Same-digest stamp cooldown: skip OpenTimestamps/FreeTSA when this SHA-256
// was successfully stamped recently. Stores only the digest plus the base64
// calendar/TSA payloads already returned to the client — never file bytes or IPs.

export const STAMP_DEDUP_DEFAULT_MS = 3600000; // 1 hour
export const STAMP_DEDUP_ERROR = 'This digest was stamped recently. Try again later.';

// 0 turns the cooldown off. Missing or invalid values use the default.
export function parseStampDedupMs(env) {
  const raw = env && env.STAMP_DEDUP_MS;
  if (raw == null || String(raw).trim() === '') return STAMP_DEDUP_DEFAULT_MS;
  const n = Number.parseInt(String(raw).trim(), 10);
  return Number.isFinite(n) && n >= 0 ? n : STAMP_DEDUP_DEFAULT_MS;
}

export function stampDedupRetryAfterSeconds(lastOkAt, windowMs, nowMs = Date.now()) {
  const ends = Number(lastOkAt) + Number(windowMs);
  return Math.max(1, Math.ceil((ends - nowMs) / 1000));
}

function parseCachedBody(row) {
  if (!row || row.ots_json == null) return null;
  try {
    const ots = JSON.parse(row.ots_json);
    if (!ots || typeof ots !== 'object' || Array.isArray(ots)) return null;
    const tsr = row.tsr == null || row.tsr === '' ? null : String(row.tsr);
    return { ots, tsr, errors: [] };
  } catch {
    return null;
  }
}

// Returns { hit: false } or { hit: true, body } or { hit: true, retryAfter }.
export async function lookupStampDedup(env, digestHex, nowMs = Date.now()) {
  const windowMs = parseStampDedupMs(env);
  if (windowMs === 0 || !env || !env.CT_DB) return { hit: false, windowMs };
  const digest = String(digestHex || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(digest)) return { hit: false, windowMs };
  try {
    const row = await env.CT_DB.prepare(
      'SELECT digest, last_ok_at, ots_json, tsr FROM stamp_dedup WHERE digest = ?',
    ).bind(digest).first();
    if (!row || row.last_ok_at == null) return { hit: false, windowMs };
    const age = nowMs - Number(row.last_ok_at);
    if (!(age >= 0) || age >= windowMs) return { hit: false, windowMs };
    const body = parseCachedBody(row);
    if (body) return { hit: true, body, windowMs, lastOkAt: Number(row.last_ok_at) };
    return {
      hit: true,
      retryAfter: stampDedupRetryAfterSeconds(row.last_ok_at, windowMs, nowMs),
      windowMs,
      lastOkAt: Number(row.last_ok_at),
    };
  } catch (e) {
    console.error(JSON.stringify({ msg: 'stamp dedup lookup error', error: String(e && e.message ? e.message : e) }));
    return { hit: false, windowMs, error: true };
  }
}

export function stampResultIsCacheable(ots, tsr) {
  return !!(tsr || (ots && typeof ots === 'object' && Object.keys(ots).length > 0));
}

export async function storeStampDedup(env, digestHex, { ots, tsr }, nowMs = Date.now()) {
  const windowMs = parseStampDedupMs(env);
  if (windowMs === 0 || !env || !env.CT_DB) return { stored: false };
  if (!stampResultIsCacheable(ots, tsr)) return { stored: false };
  const digest = String(digestHex || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(digest)) return { stored: false };
  try {
    await env.CT_DB.prepare(
      `INSERT INTO stamp_dedup (digest, last_ok_at, ots_json, tsr)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(digest) DO UPDATE SET
         last_ok_at = excluded.last_ok_at,
         ots_json = excluded.ots_json,
         tsr = excluded.tsr`,
    ).bind(digest, nowMs, JSON.stringify(ots || {}), tsr == null ? null : String(tsr)).run();
    return { stored: true };
  } catch (e) {
    console.error(JSON.stringify({ msg: 'stamp dedup store error', error: String(e && e.message ? e.message : e) }));
    return { stored: false, error: true };
  }
}

// Drop rows whose cooldown has already ended (plus a small grace if the window is 0).
export async function pruneStampDedup(env, nowMs = Date.now()) {
  if (!env || !env.CT_DB) return { pruned: false };
  const windowMs = parseStampDedupMs(env);
  const keepMs = windowMs > 0 ? windowMs : STAMP_DEDUP_DEFAULT_MS;
  const cutoff = nowMs - keepMs;
  try {
    await env.CT_DB.prepare('DELETE FROM stamp_dedup WHERE last_ok_at < ?').bind(cutoff).run();
    return { pruned: true, cutoff };
  } catch (e) {
    console.error(JSON.stringify({ msg: 'stamp dedup prune error', error: String(e && e.message ? e.message : e) }));
    return { pruned: false };
  }
}
