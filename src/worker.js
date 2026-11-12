import { runCtTick } from './ct-runtime.js';
import { mcpLaneGate, consumeMcpLaneQuota, pruneMcpLaneUsage, recordMcp429 } from './mcp-lane.js';
import { lookupStampDedup, pruneStampDedup, STAMP_DEDUP_ERROR, storeStampDedup, updateStampDedupTsr } from './stamp-dedup.js';
import { parseBearer, resolveStampCaller, sanitizeLabel, stampAuthLimitKey, stampLimitKey, timingSafeEqualHex } from './stamp-keys.js';
import { htmlResponse, jsonResponse, lookupStamp, normalizeDigest, parseReceiptPath, redirectToReceipt, wantsJson } from './receipt-lookup.js';
// LightDrawer Worker: serves the static site (Workers Static Assets) and two small
// hash-only proxies, because OpenTimestamps calendars and FreeTSA do not send CORS
// headers. No accounts, no file contents ever reach this Worker. If CT_DB is bound,
// only SHA-256 fingerprints are stored for the certificate-log stamp queue.
//   POST /api/stamp          { digest, tsq, turnstile } -> { ots: {calendar: b64}, tsr: b64, errors }
//                            Authorization: Bearer <key> skips Turnstile for trusted callers (hash stored in D1)
//                            Same-digest cooldown (STAMP_DEDUP_MS) reuses cached calendar payloads.
//                            A cached stamp with no TSR still calls FreeTSA when the request includes tsq.
//   POST /api/mcp/stamp      { digest, tsq } -> same JSON; no Turnstile, no API key; rate-limited open lane
//                            Shares performStamp() and the same-digest cooldown with /api/stamp
//   Each finished /api/stamp and /api/mcp/stamp response writes one JSON log line
//   { msg, path, status, via, limited }. via is key, turnstile, mcp, or null.
//   The line never includes a key id, label, digest, or IP. MCP 429s can also
//   emit one mcp-lane-alarm warning per UTC minute per isolate.
//   GET  /api/ots/upgrade?cal=<calendar>&commitment=<hex>  -> raw calendar timestamp bytes | 404 pending
//   GET  /api/ct/upgrade?digest=<hex>  -> anchored proofs/ct.json | 404 pending
//   GET  /r/<digest>         -> public fingerprint record (HTML; JSON if Accept: application/json)
//   GET  /?digest=<hex>      -> 302 redirect to /r/<digest>
//   GET  /?expect=<hex>      -> homepage (browser compares the dropped file hash; not a Worker lookup)
//   GET  /api/lookup?digest=<hex>  -> same record as JSON
//   GET  /api/config         -> { turnstileSiteKey }
const CALENDARS = ['https://a.pool.opentimestamps.org', 'https://b.pool.opentimestamps.org', 'https://a.pool.eternitywall.com'];
// Pending attestations name the calendar that will finish the proof; only these hosts are proxied.
const UPGRADE_HOSTS = /^(alice|bob)\.btc\.calendar\.opentimestamps\.org$|^(a|b)\.pool\.opentimestamps\.org$|^finney\.calendar\.eternitywall\.com$|^a\.pool\.eternitywall\.com$|^btc\.calendar\.catallaxy\.com$|^ots\.btc\.catallaxy\.com$/;
const TSA_URL = 'https://freetsa.org/tsr';
const UPSTREAM_TIMEOUT_MS = 10000;
const MAX_BODY = 2048;

const json = (obj, status = 200, extra = {}) => new Response(JSON.stringify(obj), {
  status,
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    ...extra,
  },
});
const hexToBytes = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const b64 = (u8) => { let s = ''; for (const c of u8) s += String.fromCharCode(c); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const clientIp = (req) => req.headers.get('cf-connecting-ip') || 'local';

async function readLimitedText(req, maxBytes) {
  const declared = Number(req.headers.get('content-length') || 0);
  if (Number.isFinite(declared) && declared > maxBytes) return { error: 'request too large' };
  if (!req.body) return { text: '' };
  const reader = req.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      try { await reader.cancel(); } catch { /* ignore */ }
      return { error: 'request too large' };
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.byteLength; }
  return { text: new TextDecoder().decode(out) };
}

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

// One structured line per finished stamp request. Do not add key ids, labels,
// digests, or IPs here — those stay off this line on purpose.
function emitStampLog(env, path, meta, response) {
  console.log(JSON.stringify({
    msg: 'stamp',
    path,
    status: response.status,
    via: meta.via,
    limited: meta.limited,
  }));
  if (path === '/api/mcp/stamp' && response.status === 429) recordMcp429(env);
  return response;
}

async function handleStamp(req, env, url) {
  const meta = { via: null, limited: false };
  const done = (response) => emitStampLog(env, '/api/stamp', meta, response);
  const ip = clientIp(req);
  // Any Bearer attempt is limited per IP before a D1 lookup, so junk keys cannot flood the database.
  // Prefer STAMP_AUTH_LIMITER (20/min) when bound; otherwise reuse STAMP_LIMITER.
  if (parseBearer(req.headers.get('authorization')).kind !== 'none') {
    const authLimiter = env.STAMP_AUTH_LIMITER || env.STAMP_LIMITER;
    if (await limited(authLimiter, stampAuthLimitKey(ip))) return done(json({ error: 'Too many requests. Try again in a minute.' }, 429));
  }
  const auth = await resolveStampCaller(req, env);
  if (auth.status === 'unavailable') return done(json({ error: 'stamp key store unavailable' }, 503));
  if (auth.status === 'unauthorized') return done(json({ error: 'Invalid or revoked API key.' }, 401));
  const caller = auth.status === 'ok' ? auth.caller : null;
  // "key" only after the key has been accepted. A rejected Bearer stays via null.
  if (caller) meta.via = 'key';
  // Browser posts stay same-origin. A valid API key is the trust signal for server callers.
  if (!caller) {
    const origin = req.headers.get('origin');
    if (origin && origin !== url.origin) return done(json({ error: 'cross-origin requests are not accepted' }, 403));
  }
  if (await limited(env.STAMP_LIMITER, stampLimitKey(caller, ip))) return done(json({ error: 'Too many requests. Try again in a minute.' }, 429));
  const raw = await readLimitedText(req, MAX_BODY * 2);
  if (raw.error) return done(json({ error: raw.error }, 413));
  let body; try { body = JSON.parse(raw.text); } catch { return done(json({ error: 'bad JSON' }, 400)); }
  if (!/^[0-9a-f]{64}$/.test(body.digest || '')) return done(json({ error: 'digest must be 64 hex chars (SHA-256)' }, 400));
  if (caller) {
    console.log(JSON.stringify({ msg: 'stamp key accepted', label: sanitizeLabel(caller.label), key_id: caller.id }));
  } else if (!(await turnstileOk(env, body.turnstile, ip))) {
    return done(json({ error: 'Human check failed or expired. Reload and try again.' }, 403));
  } else if (env.TURNSTILE_SECRET) {
    // Browser stamp that passed the human check. When Turnstile is not
    // configured, turnstileOk allows the request but via stays null.
    meta.via = 'turnstile';
  }
  const digest = hexToBytes(body.digest);
  let tsq = null;
  if (body.tsq) {
    try { tsq = unb64(body.tsq); } catch { return done(json({ error: 'bad tsq' }, 400)); }
    // A TimeStampReq for SHA-256 is ~60-90 bytes; refuse anything else and anything not for this digest.
    if (tsq.length > 256 || tsq[0] !== 0x30 || !containsDigest(tsq, digest)) return done(json({ error: 'tsq must be an RFC 3161 request for this digest' }, 400));
  }
  const result = await performStamp(env, { digestHex: body.digest, digestBytes: digest, tsq });
  if (result.status === 429) meta.limited = 'dedup';
  return done(stampResponse(result));
}

function stampResponse(result) {
  return json(result.body, result.status || 200, result.headers || {});
}

async function fetchFreeTsa(tsq) {
  try {
    const r = await fetch(TSA_URL, { method: 'POST', body: tsq, headers: { 'content-type': 'application/timestamp-query' }, signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const b = new Uint8Array(await r.arrayBuffer()); if (b.length > 20000) throw new Error('response too large');
    return { tsr: b64(b), error: null };
  } catch (e) {
    console.error(JSON.stringify({ msg: 'freetsa error', error: String(e && e.message ? e.message : e) }));
    return { tsr: null, error: 'FreeTSA: unavailable' };
  }
}

async function performStamp(env, { digestHex, digestBytes, tsq }) {
  const digest = String(digestHex || '').toLowerCase();
  const dedup = await lookupStampDedup(env, digest);
  if (dedup.hit) {
    if (dedup.body) {
      // Calendar payloads stay cached. A missing TSR is filled from FreeTSA only
      // when this request brought a tsq, and that write does not move last_ok_at.
      if (tsq && dedup.body.tsr == null) {
        const filled = await fetchFreeTsa(tsq);
        if (filled.tsr) await updateStampDedupTsr(env, digest, filled.tsr);
        return {
          status: 200,
          body: { ots: dedup.body.ots, tsr: filled.tsr, errors: filled.error ? [filled.error] : [] },
        };
      }
      return { status: 200, body: dedup.body };
    }
    return {
      status: 429,
      body: { error: STAMP_DEDUP_ERROR },
      headers: { 'retry-after': String(dedup.retryAfter) },
    };
  }

  const errors = [], ots = {};
  const otsJobs = CALENDARS.map(async (cal) => {
    try {
      const r = await fetch(cal + '/digest', { method: 'POST', body: digestBytes, headers: { accept: 'application/vnd.opentimestamps.v1', 'user-agent': 'lightdrawer-proxy' }, signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const b = new Uint8Array(await r.arrayBuffer()); if (b.length > 10000) throw new Error('response too large');
      ots[cal] = b64(b);
    } catch (e) {
      console.error(JSON.stringify({ msg: 'ots calendar error', calendar: cal, error: String(e && e.message ? e.message : e) }));
      errors.push(`OpenTimestamps ${cal}: unavailable`);
    }
  });
  let tsr = null;
  const tsaJob = tsq ? (async () => {
    const filled = await fetchFreeTsa(tsq);
    tsr = filled.tsr;
    if (filled.error) errors.push(filled.error);
  })() : Promise.resolve();
  await Promise.all([...otsJobs, tsaJob]);
  // Optional CT queue: store only the 32-byte hash, and only if a D1 binding is present.
  if (env.CT_DB) {
    try {
      await env.CT_DB.prepare('INSERT OR IGNORE INTO ct_pending (digest, received_at) VALUES (?, ?)').bind(digest, new Date().toISOString()).run();
    } catch (e) {
      console.error(JSON.stringify({ msg: 'ct queue error', error: String(e && e.message ? e.message : e) }));
      errors.push('CT queue: unavailable');
    }
  }
  await storeStampDedup(env, digest, { ots, tsr });
  return { status: 200, body: { ots, tsr, errors } };
}

async function handleMcpStamp(req, env) {
  const meta = { via: 'mcp', limited: false };
  const done = (response) => emitStampLog(env, '/api/mcp/stamp', meta, response);
  const gate = await mcpLaneGate(env);
  if (!gate.allow) {
    if (gate.status === 404) return done(json({ error: 'not found' }, 404));
    return done(json({ error: 'stamp lane unavailable' }, 503));
  }
  const ip = clientIp(req);
  if (await limited(env.MCP_STAMP_LIMITER, 'mcp-stamp:' + ip)) {
    meta.limited = 'burst';
    return done(json({ error: 'Too many requests. Try again later.' }, 429, { 'retry-after': '10' }));
  }
  const raw = await readLimitedText(req, MAX_BODY * 2);
  if (raw.error) return done(json({ error: raw.error }, 413));
  let body;
  try { body = JSON.parse(raw.text); } catch { return done(json({ error: 'bad JSON' }, 400)); }
  if (!/^[0-9a-f]{64}$/.test(body.digest || '')) return done(json({ error: 'digest must be 64 hex chars (SHA-256)' }, 400));
  const digest = hexToBytes(body.digest);
  let tsq = null;
  if (body.tsq) {
    try { tsq = unb64(body.tsq); } catch { return done(json({ error: 'bad tsq' }, 400)); }
    if (tsq.length > 256 || tsq[0] !== 0x30 || !containsDigest(tsq, digest)) return done(json({ error: 'tsq must be an RFC 3161 request for this digest' }, 400));
  }
  const quota = await consumeMcpLaneQuota(env, ip);
  if (quota.unavailable) return done(json({ error: 'stamp lane unavailable' }, 503));
  if (quota.limited) {
    meta.limited = quota.scope === 'global' ? 'global' : 'ip';
    return done(json({ error: 'Too many requests. Try again later.' }, 429, { 'retry-after': String(quota.retryAfter) }));
  }
  const result = await performStamp(env, { digestHex: body.digest, digestBytes: digest, tsq });
  if (result.status === 429) meta.limited = 'dedup';
  return done(stampResponse(result));
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

async function handleCtTick(req, env) {
  if (!env.CT_TICK_SECRET) return json({ error: 'not found' }, 404);
  const ip = clientIp(req);
  const tickLimiter = env.STAMP_AUTH_LIMITER || env.STAMP_LIMITER || env.UPGRADE_LIMITER;
  if (await limited(tickLimiter, 'ct-tick:' + ip)) return json({ error: 'Too many requests. Try again in a minute.' }, 429);
  const auth = req.headers.get('authorization') || '';
  const got = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!(await timingSafeEqualHex(got, env.CT_TICK_SECRET))) return json({ error: 'unauthorized' }, 401);
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
      if (req.method !== 'POST') return emitStampLog(env, '/api/stamp', { via: null, limited: false }, json({ error: 'POST only' }, 405));
      // Same-origin only for browser posts (no CORS headers). A valid API key may come from another origin.
      return handleStamp(req, env, url);
    }
    if (url.pathname === '/api/mcp/stamp') {
      if (req.method !== 'POST') return emitStampLog(env, '/api/mcp/stamp', { via: 'mcp', limited: false }, json({ error: 'POST only' }, 405));
      return handleMcpStamp(req, env);
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
    await pruneMcpLaneUsage(env);
    await pruneStampDedup(env);
    await runCtTick(env, { force: false, includeOpen: false });
  },
};
