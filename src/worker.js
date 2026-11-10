import { runCtTick } from './ct-runtime.js';
import { parseBearer, resolveStampCaller, sanitizeLabel, stampAuthLimitKey, stampLimitKey } from './stamp-keys.js';
import { htmlResponse, jsonResponse, lookupStamp, normalizeDigest, parseReceiptPath, redirectToReceipt, wantsJson } from './receipt-lookup.js';
// LightDrawer Worker: serves the static site (Workers Static Assets) and two small
// hash-only proxies, because OpenTimestamps calendars and FreeTSA do not send CORS
// headers. No accounts, no file contents ever reach this Worker. If CT_DB is bound,
// only SHA-256 fingerprints are stored for the certificate-log stamp queue.
//   POST /api/stamp          { digest, tsq, turnstile } -> { ots: {calendar: b64}, tsr: b64, errors }
//                            Authorization: Bearer <key> skips Turnstile for trusted callers (hash stored in D1)
//   GET  /api/ots/upgrade?cal=<calendar>&commitment=<hex>  -> raw calendar timestamp bytes | 404 pending
//   GET  /api/ct/upgrade?digest=<hex>  -> anchored proofs/ct.json | 404 pending
//   GET  /r/<digest>         -> public fingerprint record (HTML; JSON if Accept: application/json)
//   GET  /?digest=<hex>      -> 302 redirect to /r/<digest>
//   GET  /api/lookup?digest=<hex>  -> same record as JSON
//   GET  /api/config         -> { turnstileSiteKey }
const CALENDARS = ['https://a.pool.opentimestamps.org', 'https://b.pool.opentimestamps.org', 'https://a.pool.eternitywall.com'];
// Pending attestations name the calendar that will finish the proof; only these hosts are proxied.
const UPGRADE_HOSTS = /^(alice|bob)\.btc\.calendar\.opentimestamps\.org$|^(a|b)\.pool\.opentimestamps\.org$|^finney\.calendar\.eternitywall\.com$|^a\.pool\.eternitywall\.com$|^btc\.calendar\.catallaxy\.com$|^ots\.btc\.catallaxy\.com$/;
const TSA_URL = 'https://freetsa.org/tsr';
const UPSTREAM_TIMEOUT_MS = 10000;
const MAX_BODY = 2048;

const json = (obj, status = 200, extra = {}) => new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra } });
const hexToBytes = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const b64 = (u8) => { let s = ''; for (const c of u8) s += String.fromCharCode(c); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const clientIp = (req) => req.headers.get('cf-connecting-ip') || 'local';

async function limited(binding, key) {
  if (!binding) return false; // binding absent (e.g. some local setups): rely on WAF rule instead
  const { success } = await binding.limit({ key });
  return !success;
}

async function turnstileOk(env, token, ip) {
  if (!env.TURNSTILE_SECRET) return true; // not configured: allowed (local dev). Configure before going public.
  if (!token || typeof token !== 'string' || token.length > 2048) return false;
  const form = new FormData(); form.append('secret', env.TURNSTILE_SECRET); form.append('response', token); form.append('remoteip', ip);
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
  const j = await r.json().catch(() => ({}));
  return j.success === true;
}

function containsDigest(tsq, digest) {
  outer: for (let i = 0; i + digest.length <= tsq.length; i++) { for (let j = 0; j < digest.length; j++) if (tsq[i + j] !== digest[j]) continue outer; return true; }
  return false;
}

async function handleStamp(req, env, url) {
  const ip = clientIp(req);
  // Any Bearer attempt is limited per IP before a D1 lookup, so junk keys cannot flood the database.
  // Prefer STAMP_AUTH_LIMITER (20/min) when bound; otherwise reuse STAMP_LIMITER.
  if (parseBearer(req.headers.get('authorization')).kind !== 'none') {
    const authLimiter = env.STAMP_AUTH_LIMITER || env.STAMP_LIMITER;
    if (await limited(authLimiter, stampAuthLimitKey(ip))) return json({ error: 'Too many requests. Try again in a minute.' }, 429);
  }
  const auth = await resolveStampCaller(req, env);
  if (auth.status === 'unavailable') return json({ error: 'stamp key store unavailable' }, 503);
  if (auth.status === 'unauthorized') return json({ error: 'Invalid or revoked API key.' }, 401);
  const caller = auth.status === 'ok' ? auth.caller : null;
  // Browser posts stay same-origin. A valid API key is the trust signal for server callers.
  if (!caller) {
    const origin = req.headers.get('origin');
    if (origin && origin !== url.origin) return json({ error: 'cross-origin requests are not accepted' }, 403);
  }
  if (await limited(env.STAMP_LIMITER, stampLimitKey(caller, ip))) return json({ error: 'Too many requests. Try again in a minute.' }, 429);
  const len = Number(req.headers.get('content-length') || 0);
  if (len > MAX_BODY * 2) return json({ error: 'request too large' }, 413);
  let body; try { body = JSON.parse(await req.text()); } catch { return json({ error: 'bad JSON' }, 400); }
  if (!/^[0-9a-f]{64}$/.test(body.digest || '')) return json({ error: 'digest must be 64 hex chars (SHA-256)' }, 400);
  if (caller) {
    console.log(JSON.stringify({ msg: 'stamp key accepted', label: sanitizeLabel(caller.label), key_id: caller.id }));
  } else if (!(await turnstileOk(env, body.turnstile, ip))) {
    return json({ error: 'Human check failed or expired. Reload and try again.' }, 403);
  }
  const digest = hexToBytes(body.digest);
  let tsq = null;
  if (body.tsq) {
    try { tsq = unb64(body.tsq); } catch { return json({ error: 'bad tsq' }, 400); }
    // A TimeStampReq for SHA-256 is ~60-90 bytes; refuse anything else and anything not for this digest.
    if (tsq.length > 256 || tsq[0] !== 0x30 || !containsDigest(tsq, digest)) return json({ error: 'tsq must be an RFC 3161 request for this digest' }, 400);
  }
  const errors = [], ots = {};
  const otsJobs = CALENDARS.map(async (cal) => {
    try {
      const r = await fetch(cal + '/digest', { method: 'POST', body: digest, headers: { accept: 'application/vnd.opentimestamps.v1', 'user-agent': 'lightdrawer-proxy' }, signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const b = new Uint8Array(await r.arrayBuffer()); if (b.length > 10000) throw new Error('response too large');
      ots[cal] = b64(b);
    } catch (e) { errors.push(`OpenTimestamps ${cal}: ${e.message}`); }
  });
  let tsr = null;
  const tsaJob = tsq ? (async () => {
    try {
      const r = await fetch(TSA_URL, { method: 'POST', body: tsq, headers: { 'content-type': 'application/timestamp-query' }, signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const b = new Uint8Array(await r.arrayBuffer()); if (b.length > 20000) throw new Error('response too large');
      tsr = b64(b);
    } catch (e) { errors.push(`FreeTSA: ${e.message}`); }
  })() : Promise.resolve();
  await Promise.all([...otsJobs, tsaJob]);
  // Optional CT queue: store only the 32-byte hash, and only if a D1 binding is present.
  if (env.CT_DB) {
    try {
      await env.CT_DB.prepare('INSERT OR IGNORE INTO ct_pending (digest, received_at) VALUES (?, ?)').bind(body.digest.toLowerCase(), new Date().toISOString()).run();
    } catch (e) { errors.push('CT queue: ' + e.message); }
  }
  return json({ ots, tsr, errors });
}

async function handleUpgrade(req, env, url, ctx) {
  const cors = { 'access-control-allow-origin': '*' }; // verify.html may run from file:// (Origin: null)
  const ip = clientIp(req);
  if (await limited(env.UPGRADE_LIMITER, 'upgrade:' + ip)) return json({ error: 'rate limited' }, 429, cors);
  const cal = url.searchParams.get('cal') || '', commitment = (url.searchParams.get('commitment') || '').toLowerCase();
  let host; try { const u = new URL(cal); if (u.protocol !== 'https:' || u.pathname.replace(/\/$/, '') !== '' || u.search) throw 0; host = u.hostname; } catch { return json({ error: 'bad calendar URL' }, 400, cors); }
  if (!UPGRADE_HOSTS.test(host)) return json({ error: 'calendar not on allowlist' }, 400, cors);
  if (!/^[0-9a-f]{2,512}$/.test(commitment) || commitment.length % 2) return json({ error: 'bad commitment' }, 400, cors);
  const cacheKey = new Request(`https://lightdrawer-cache.invalid/ots/${host}/${commitment}`);
  const cache = caches.default;
  const hit = await cache.match(cacheKey); if (hit) return hit;
  let r;
  try { r = await fetch(`https://${host}/timestamp/${commitment}`, { headers: { accept: 'application/vnd.opentimestamps.v1' }, signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) }); }
  catch (e) { return json({ error: 'calendar unreachable' }, 502, cors); }
  if (r.status === 404) return json({ pending: true }, 404, { ...cors, 'cache-control': 'public, max-age=300' });
  if (!r.ok) return json({ error: 'calendar HTTP ' + r.status }, 502, cors);
  const bytes = new Uint8Array(await r.arrayBuffer());
  if (bytes.length > 20000) return json({ error: 'response too large' }, 502, cors);
  const resp = new Response(bytes, { headers: { ...cors, 'content-type': 'application/vnd.opentimestamps.v1', 'cache-control': 'public, max-age=3600' } });
  ctx.waitUntil(cache.put(cacheKey, resp.clone()));
  return resp;
}

async function handleCtUpgrade(req, env, url) {
  const cors = { 'access-control-allow-origin': '*' }; // verify.html may run from file://
  const ip = clientIp(req);
  if (await limited(env.UPGRADE_LIMITER, 'ct-upgrade:' + ip)) return json({ error: 'rate limited' }, 429, cors);
  const digest = (url.searchParams.get('digest') || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(digest)) return json({ error: 'digest must be 64 hex chars (SHA-256)' }, 400, cors);
  if (!env.CT_DB) return json({ pending: true }, 404, { ...cors, 'cache-control': 'public, max-age=60' });
  try {
    const row = await env.CT_DB.prepare(
      `SELECT b.published, b.hostname, b.root, b.tree_size, b.leaves_json, b.proofs_json, b.id AS batch_id,
              b.opened_at, b.closed_at, c.issued_at, c.certificate_pem, c.chain_pems_json, c.scts_json
         FROM ct_leaves l
         JOIN ct_batches b ON b.id = l.batch_id
         LEFT JOIN ct_certs c ON c.id = b.cert_id
        WHERE l.digest = ?`
    ).bind(digest).first();
    if (!row) {
      const pending = await env.CT_DB.prepare('SELECT digest FROM ct_pending WHERE digest = ?').bind(digest).first();
      return json({ pending: true, queued: !!pending }, 404, { ...cors, 'cache-control': 'public, max-age=60' });
    }
    if (!row.published || !row.certificate_pem) {
      return json({ pending: true, status: 'pending', hostname: row.hostname }, 404, { ...cors, 'cache-control': 'public, max-age=60' });
    }
    const proofs = JSON.parse(row.proofs_json);
    const proof = proofs[digest];
    return json({
      lightdrawer_ct: 1,
      status: 'anchored',
      digest,
      merkle: { leaf_index: proof.index, tree_size: row.tree_size, path: proof.path, root: row.root, algorithm: 'RFC 6962 SHA-256' },
      hostname: row.hostname,
      certificate_pem: row.certificate_pem,
      chain_pems: JSON.parse(row.chain_pems_json || '[]'),
      scts: JSON.parse(row.scts_json || '[]'),
      crtsh_url: 'https://crt.sh/?q=' + encodeURIComponent(row.hostname),
      sub_batch: { id: row.batch_id, opened_at: row.opened_at, closed_at: row.closed_at },
      issued_at: row.issued_at,
    }, 200, cors);
  } catch (e) {
    return json({ error: 'CT store error' }, 502, cors);
  }
}


async function handleReceiptLookup(req, env, url) {
  const origin = url.origin;
  const asJson = wantsJson(req, url.pathname);
  const respond = (opts) => (asJson ? jsonResponse(req, opts) : htmlResponse(req, { ...opts, origin }));
  if (req.method !== 'GET' && req.method !== 'HEAD') return json({ error: 'GET only' }, 405);
  let digest = null;
  if (url.pathname === '/api/lookup') {
    digest = normalizeDigest(url.searchParams.get('digest') || '');
    if (!digest) return respond({ kind: 'malformed', digest: null, status: 400 });
  } else {
    const parsed = parseReceiptPath(url.pathname);
    if (!parsed) return respond({ kind: 'malformed', digest: null, status: 400 });
    if (parsed.kind === 'empty' || parsed.kind === 'malformed') return respond({ kind: 'malformed', digest: null, status: 400 });
    if (parsed.needsCanonical && req.method === 'GET' && !asJson) return redirectToReceipt(origin, parsed.digest);
    digest = parsed.digest;
  }
  if (!env.CT_DB) return respond({ kind: 'not_found', digest, record: { found: false, digest }, status: 404 });
  try {
    const record = await lookupStamp(env.CT_DB, digest);
    if (!record.found) return respond({ kind: 'not_found', digest, record, status: 404 });
    return respond({ kind: 'found', digest, record, status: 200 });
  } catch (e) {
    return respond({ kind: 'error', digest, status: 502 });
  }
}

async function handleDigestQuery(req, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return new Response('GET only', { status: 405 });
  const digest = normalizeDigest(url.searchParams.get('digest') || '');
  if (!digest) {
    if (wantsJson(req, url.pathname)) return jsonResponse(req, { kind: 'malformed', digest: null, status: 400 });
    return htmlResponse(req, { kind: 'malformed', digest: null, origin: url.origin, status: 400 });
  }
  return redirectToReceipt(url.origin, digest);
}

function safeEqual(a, b) {
  const enc = new TextEncoder();
  const ba = enc.encode(String(a || '')), bb = enc.encode(String(b || ''));
  if (ba.length !== bb.length) return false;
  let d = 0;
  for (let i = 0; i < ba.length; i++) d |= ba[i] ^ bb[i];
  return d === 0;
}

async function handleCtTick(req, env) {
  if (!env.CT_TICK_SECRET) return json({ error: 'not found' }, 404);
  const auth = req.headers.get('authorization') || '';
  const got = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!safeEqual(got, env.CT_TICK_SECRET)) return json({ error: 'unauthorized' }, 401);
  let body = {};
  try {
    const ct = req.headers.get('content-type') || '';
    if (ct.includes('json')) body = await req.json();
  } catch { body = {}; }
  const force = body.force === true;
  return json(await runCtTick(env, { force, includeOpen: force }));
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (url.pathname === '/' && url.searchParams.has('digest')) return handleDigestQuery(req, url);
    if (url.pathname === '/r' || url.pathname.startsWith('/r/')) return handleReceiptLookup(req, env, url);
    if (url.pathname === '/api/lookup') {
      if (req.method === 'OPTIONS') return json({ error: 'GET only' }, 405);
      return handleReceiptLookup(req, env, url);
    }
    if (url.pathname === '/api/config' && req.method === 'GET') return json({ turnstileSiteKey: env.TURNSTILE_SITE_KEY || '' });
    if (url.pathname === '/api/ct/tick') {
      if (req.method !== 'POST') return json({ error: 'POST only' }, 405);
      return handleCtTick(req, env);
    }
    if (url.pathname === '/api/stamp') {
      if (req.method !== 'POST') return json({ error: 'POST only' }, 405);
      // Same-origin only for browser posts (no CORS headers). A valid API key may come from another origin.
      return handleStamp(req, env, url);
    }
    if (url.pathname === '/api/ots/upgrade') {
      if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET', 'access-control-max-age': '86400' } });
      if (req.method !== 'GET') return json({ error: 'GET only' }, 405);
      return handleUpgrade(req, env, url, ctx);
    }
    if (url.pathname === '/api/ct/upgrade') {
      if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET', 'access-control-max-age': '86400' } });
      if (req.method !== 'GET') return json({ error: 'GET only' }, 405);
      return handleCtUpgrade(req, env, url);
    }
    if (url.pathname.startsWith('/api/')) return json({ error: 'not found' }, 404);
    return env.ASSETS.fetch(req);
  },
  async scheduled(event, env, ctx) {
    await runCtTick(env, { force: false, includeOpen: false });
  },
};
