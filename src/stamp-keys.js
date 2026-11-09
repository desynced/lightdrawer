// Trusted-caller API keys for POST /api/stamp.
// Only SHA-256 hashes are stored (D1 stamp_keys). The plaintext key is shown
// once at mint time and never written to the repo or the receipt.
const MAX_KEY_LEN = 256;
const HASH_HEX_RE = /^[0-9a-f]{64}$/;
export const STAMP_KEY_LABEL_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;

const hexFromBuf = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

export async function hashStampKey(token) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(token)));
  return hexFromBuf(digest);
}

export function timingSafeEqualBytes(a, b) {
  const ua = a instanceof Uint8Array ? a : new Uint8Array(a);
  const ub = b instanceof Uint8Array ? b : new Uint8Array(b);
  const eq = crypto.subtle && typeof crypto.subtle.timingSafeEqual === 'function'
    ? (x, y) => crypto.subtle.timingSafeEqual(x, y)
    : (x, y) => {
      let d = 0;
      for (let i = 0; i < x.byteLength; i++) d |= x[i] ^ y[i];
      return d === 0;
    };
  // Always compare something of equal length so a mismatch does not leak size.
  if (ua.byteLength !== ub.byteLength) {
    eq(ua, ua);
    return false;
  }
  return eq(ua, ub);
}

export async function timingSafeEqualHex(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(String(a || ''))),
    crypto.subtle.digest('SHA-256', enc.encode(String(b || ''))),
  ]);
  return timingSafeEqualBytes(ha, hb);
}

// Returns { kind: 'none' } for missing/other schemes (browser path),
// { kind: 'invalid' } for a broken Bearer attempt,
// { kind: 'token', token } for a present Bearer token.
export function parseBearer(header) {
  if (header == null || header === '') return { kind: 'none' };
  const m = /^(Bearer)(?: +(.*))?$/i.exec(String(header));
  if (!m) return { kind: 'none' };
  const token = (m[2] || '').trim();
  if (!token || token.length > MAX_KEY_LEN || /\s/.test(token)) return { kind: 'invalid' };
  return { kind: 'token', token };
}

function b64url(bytes) {
  let s = '';
  for (const c of bytes) s += String.fromCharCode(c);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export async function generateStampKeyRecord(label) {
  if (!STAMP_KEY_LABEL_RE.test(label)) {
    throw new Error('label must be 1–64 characters: start with a letter or digit, then letters, digits, ".", "_" or "-"');
  }
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const token = 'ldsk_' + b64url(bytes);
  return {
    id: crypto.randomUUID(),
    label,
    token,
    key_hash: await hashStampKey(token),
    created_at: new Date().toISOString(),
  };
}

export function insertStampKeySql({ id, label, key_hash, created_at }) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) throw new Error('id must be a UUID');
  if (!STAMP_KEY_LABEL_RE.test(label)) throw new Error('invalid label');
  if (!HASH_HEX_RE.test(key_hash)) throw new Error('key_hash must be 64 lowercase hex characters');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(created_at)) throw new Error('created_at must be an ISO timestamp');
  return `INSERT INTO stamp_keys (id, label, key_hash, created_at, revoked_at) VALUES ('${id}', '${label}', '${key_hash}', '${created_at}', NULL);`;
}

export function revokeStampKeySql(id, revoked_at = new Date().toISOString()) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) throw new Error('id must be a UUID');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(revoked_at)) throw new Error('revoked_at must be an ISO timestamp');
  return `UPDATE stamp_keys SET revoked_at = '${revoked_at}' WHERE id = '${id}' AND revoked_at IS NULL;`;
}

// status: 'anonymous' | 'ok' | 'unauthorized' | 'unavailable'
export async function resolveStampCaller(req, env) {
  const parsed = parseBearer(req.headers.get('authorization'));
  if (parsed.kind === 'none') return { status: 'anonymous' };
  if (parsed.kind === 'invalid') return { status: 'unauthorized' };
  const digest = await hashStampKey(parsed.token);
  if (!env.CT_DB) {
    console.error(JSON.stringify({ msg: 'stamp key presented but CT_DB is not bound' }));
    return { status: 'unauthorized' };
  }
  let row;
  try {
    row = await env.CT_DB.prepare(
      'SELECT id, label, key_hash, revoked_at FROM stamp_keys WHERE key_hash = ?'
    ).bind(digest).first();
  } catch (e) {
    console.error(JSON.stringify({ msg: 'stamp key lookup failed', error: String(e && e.message ? e.message : e) }));
    return { status: 'unavailable' };
  }
  const stored = (row && HASH_HEX_RE.test(row.key_hash) && row.key_hash) || '0'.repeat(64);
  const match = await timingSafeEqualHex(digest, stored);
  if (!row || !match || row.revoked_at) {
    if (row && match && row.revoked_at) {
      console.log(JSON.stringify({ msg: 'stamp key revoked', label: sanitizeLabel(row.label), key_id: String(row.id || '') }));
    }
    return { status: 'unauthorized' };
  }
  return { status: 'ok', caller: { id: String(row.id), label: String(row.label) } };
}

export function sanitizeLabel(label) {
  return String(label || '').replace(/[^\w.[\]@+-]/g, '_').slice(0, 64);
}

export function stampLimitKey(caller, ip) {
  return caller ? ('stamp:key:' + caller.id) : ('stamp:' + ip);
}

// Per-IP bucket for any request that presents a Bearer header, checked before D1.
export function stampAuthLimitKey(ip) {
  return 'stamp:auth:' + ip;
}
