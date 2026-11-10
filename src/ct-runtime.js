// Certificate-log stamp runtime for the Worker (and Node tests).
// Closes 15-minute Merkle sub-batches in D1 and issues a Let's Encrypt
// certificate covering those batch-root hostnames via DNS-01, in two phases
// so each cron tick stays within Worker time limits.
//
// Production ACME directories are allowed only when CT_PRODUCTION=1.
// The ACME directory config defaults to Let's Encrypt staging. DNS writes
// are allowed only for temporary TXT records matching:
//   _acme-challenge.<32hex>.<32hex>.ct.lightdrawer.org

export const STAGING_DIRECTORY = 'https://acme-staging-v02.api.letsencrypt.org/directory';
export const PRODUCTION_DIRECTORIES = [
  'https://acme-v02.api.letsencrypt.org/directory',
  'https://acme-v01.api.letsencrypt.org/directory',
];
export const DEFAULT_HOSTNAME_SUFFIX = 'ct.lightdrawer.org';
export const DEFAULT_SUB_BATCH_MS = 15 * 60 * 1000;
export const DEFAULT_ANCHOR_EVERY_MS = 6 * 60 * 60 * 1000;
export const DEFAULT_MAX_SANS = 100;
export const ACME_TXT_NAME_RE = /^_acme-challenge\.[0-9a-f]{32}\.[0-9a-f]{32}\.ct\.lightdrawer\.org$/;

export function isProductionDirectory(url) {
  const u = String(url || '').replace(/\/+$/, '');
  const known = new Set(PRODUCTION_DIRECTORIES);
  return known.has(u) || known.has(u + '/directory') || /acme-v0[12]\.api\.letsencrypt\.org/i.test(u);
}

export function assertAcmeDirectoryAllowed(url, env) {
  if (!isProductionDirectory(url)) return;
  if (String((env && env.CT_PRODUCTION) || '') === '1') return;
  throw new Error("Refusing to use the Let's Encrypt PRODUCTION ACME directory unless CT_PRODUCTION=1. Staging remains the safe default. Directory was: " + url);
}

// Kept as a named export so older tests and callers keep working.
// Without CT_PRODUCTION=1 this still refuses production directories.
export function assertNotProductionDirectory(url, env) {
  assertAcmeDirectoryAllowed(url, env);
}

export function acmeAccountMetaKey(directoryUrl) {
  return isProductionDirectory(directoryUrl) ? 'acme_account_production' : 'acme_account';
}

export function assertAllowedAcmeTxtName(fqdn) {
  const n = String(fqdn || '').toLowerCase().replace(/\.$/, '');
  if (!ACME_TXT_NAME_RE.test(n)) {
    throw new Error('refusing DNS write: name is not an allowed ACME challenge under ct.lightdrawer.org: ' + fqdn);
  }
  return n;
}

export function ctConfigFromEnv(env) {
  const directory = (env && env.ACME_DIRECTORY) || STAGING_DIRECTORY;
  assertAcmeDirectoryAllowed(directory, env);
  const subBatchMs = Number((env && env.CT_SUB_BATCH_MS) || DEFAULT_SUB_BATCH_MS);
  const anchorEveryMs = Number((env && env.CT_ANCHOR_EVERY_MS) || DEFAULT_ANCHOR_EVERY_MS);
  const maxSans = Number((env && env.CT_MAX_SANS) || DEFAULT_MAX_SANS);
  if (!(subBatchMs >= 60 * 1000)) throw new Error('CT_SUB_BATCH_MS must be at least 60000');
  if (!(anchorEveryMs >= subBatchMs)) throw new Error('CT_ANCHOR_EVERY_MS must be at least one sub-batch');
  if (!(maxSans >= 1 && maxSans <= 100)) throw new Error('CT_MAX_SANS must be 1–100');
  return {
    directory,
    hostnameSuffix: ((env && env.CT_HOSTNAME_SUFFIX) || DEFAULT_HOSTNAME_SUFFIX).toLowerCase().replace(/^\.+|\.+$/g, ''),
    subBatchMs,
    anchorEveryMs,
    maxSans,
    zoneId: env && env.CF_ZONE_ID,
  };
}

export function concat(...parts) {
  const arrs = parts.map((p) => (p instanceof Uint8Array ? p : new Uint8Array(p)));
  const out = new Uint8Array(arrs.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of arrs) { out.set(p, o); o += p.length; }
  return out;
}
export function toHex(u8) { return [...u8].map((b) => b.toString(16).padStart(2, '0')).join(''); }
export function fromHex(h) {
  const s = String(h).toLowerCase();
  if (!/^[0-9a-f]*$/.test(s) || s.length % 2) throw new Error('bad hex');
  return Uint8Array.from(s.match(/../g) || [], (x) => parseInt(x, 16));
}
export function utf8(s) { return new TextEncoder().encode(s); }
function toB64(u8) { let s = ''; for (const c of u8) s += String.fromCharCode(c); return btoa(s); }
export function b64url(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return toB64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function b64urlJson(obj) { return b64url(utf8(JSON.stringify(obj))); }
export async function sha256(data) { return new Uint8Array(await crypto.subtle.digest('SHA-256', data)); }

export function ctRootToHostname(rootHex, suffix) {
  const h = String(rootHex).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('root must be 32-byte SHA-256 hex');
  suffix = (suffix || DEFAULT_HOSTNAME_SUFFIX).toLowerCase().replace(/^\.+|\.+$/g, '');
  return h.slice(0, 32) + '.' + h.slice(32) + '.' + suffix;
}

function largestPowerOf2LessThan(n) { let k = 1; while ((k << 1) < n) k <<= 1; return k; }
async function merkleTreeHash(leafHashes) {
  const n = leafHashes.length;
  if (n === 0) return sha256(new Uint8Array(0));
  if (n === 1) return leafHashes[0];
  const k = largestPowerOf2LessThan(n);
  return sha256(concat(Uint8Array.of(1), await merkleTreeHash(leafHashes.slice(0, k)), await merkleTreeHash(leafHashes.slice(k))));
}
async function auditPath(index, leafHashes) {
  const n = leafHashes.length;
  if (n <= 1) return [];
  const k = largestPowerOf2LessThan(n);
  if (index < k) {
    const path = await auditPath(index, leafHashes.slice(0, k));
    path.push(await merkleTreeHash(leafHashes.slice(k)));
    return path;
  }
  const path = await auditPath(index - k, leafHashes.slice(k));
  path.push(await merkleTreeHash(leafHashes.slice(0, k)));
  return path;
}
export async function ctMerkleBuild(digestHexes) {
  const uniq = [...new Set(digestHexes.map((d) => String(d).toLowerCase()))].sort();
  if (uniq.some((d) => !/^[0-9a-f]{64}$/.test(d))) throw new Error('each digest must be 64 hex chars');
  const leafHashes = [];
  for (const d of uniq) leafHashes.push(await sha256(concat(Uint8Array.of(0), fromHex(d))));
  const root = await merkleTreeHash(leafHashes);
  const proofs = {};
  for (let i = 0; i < uniq.length; i++) {
    const path = await auditPath(i, leafHashes);
    proofs[uniq[i]] = { index: i, path: path.map(toHex) };
  }
  return { root: toHex(root), tree_size: uniq.length, leaves: uniq, proofs };
}

function windowStart(ts, subBatchMs) { return Math.floor(ts / subBatchMs) * subBatchMs; }

export async function metaGet(db, key) {
  const row = await db.prepare('SELECT value FROM ct_meta WHERE key = ?').bind(key).first();
  return row ? row.value : null;
}
export async function metaSet(db, key, value) {
  await db.prepare('INSERT INTO ct_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(key, value).run();
}
export async function metaDel(db, key) {
  await db.prepare('DELETE FROM ct_meta WHERE key = ?').bind(key).run();
}

async function uniqueBatchId(db, ws) {
  const base = new Date(ws).toISOString();
  if (!(await db.prepare('SELECT id FROM ct_batches WHERE id = ?').bind(base).first())) return base;
  // A previous close (often a forced tick) already used this window id.
  // Give leftovers a unique id so cron does not crash and they still get certified.
  for (let n = 2; n < 1000; n++) {
    const alt = base + '#' + n;
    if (!(await db.prepare('SELECT id FROM ct_batches WHERE id = ?').bind(alt).first())) return alt;
  }
  return base + '#' + Date.now();
}

export async function closeDueSubBatches(db, now, opts) {
  const includeOpen = !!(opts && opts.includeOpen);
  const subBatchMs = (opts && opts.subBatchMs) || DEFAULT_SUB_BATCH_MS;
  const suffix = (opts && opts.hostnameSuffix) || DEFAULT_HOSTNAME_SUFFIX;
  const nowMs = (now instanceof Date ? now : new Date(now || Date.now())).getTime();
  const currentStart = windowStart(nowMs, subBatchMs);
  const pending = (await db.prepare('SELECT digest, received_at FROM ct_pending').all()).results || [];
  const groups = new Map(), keep = [];
  for (const p of pending) {
    const ws = windowStart(Date.parse(p.received_at), subBatchMs);
    if (ws < currentStart || includeOpen) {
      if (!groups.has(ws)) groups.set(ws, []);
      groups.get(ws).push(p);
    } else keep.push(p);
  }
  const closed = [];
  for (const [ws, items] of [...groups.entries()].sort((a, b) => a[0] - b[0])) {
    const seen = [];
    for (const item of items) {
      const already = await db.prepare('SELECT digest FROM ct_leaves WHERE digest = ?').bind(item.digest).first();
      if (!already) seen.push(item.digest);
    }
    if (!seen.length) {
      for (const item of items) await db.prepare('DELETE FROM ct_pending WHERE digest = ?').bind(item.digest).run();
      continue;
    }
    const tree = await ctMerkleBuild(seen);
    const hostname = ctRootToHostname(tree.root, suffix);
    const id = await uniqueBatchId(db, ws);
    const batch = {
      id,
      opened_at: new Date(ws).toISOString(),
      closed_at: new Date(ws + subBatchMs).toISOString(),
      root: tree.root,
      tree_size: tree.tree_size,
      hostname,
    };
    await db.prepare(
      `INSERT INTO ct_batches (id, opened_at, closed_at, root, tree_size, leaves_json, proofs_json, hostname, published, cert_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)`
    ).bind(batch.id, batch.opened_at, batch.closed_at, batch.root, batch.tree_size, JSON.stringify(tree.leaves), JSON.stringify(tree.proofs), batch.hostname).run();
    for (const digest of tree.leaves) {
      await db.prepare('INSERT OR IGNORE INTO ct_leaves (digest, batch_id) VALUES (?, ?)').bind(digest, batch.id).run();
      await db.prepare('DELETE FROM ct_pending WHERE digest = ?').bind(digest).run();
    }
    closed.push({ ...batch, tree_size: tree.tree_size });
  }
  return closed;
}

export async function planAnchor(db, now, opts) {
  const force = !!(opts && opts.force);
  const anchorEveryMs = (opts && opts.anchorEveryMs) || DEFAULT_ANCHOR_EVERY_MS;
  const maxSans = (opts && opts.maxSans) || DEFAULT_MAX_SANS;
  const nowMs = (now instanceof Date ? now : new Date(now || Date.now())).getTime();
  const last = await metaGet(db, 'last_anchor_at');
  if (!force) {
    const attempt = await metaGet(db, 'last_attempt_at');
    const times = [last, attempt].filter(Boolean).map((v) => Date.parse(v));
    if (times.length && nowMs - Math.max(...times) < anchorEveryMs) return null;
  }
  const rows = (await db.prepare('SELECT id, hostname, root FROM ct_batches WHERE published = 0 ORDER BY id LIMIT ?').bind(maxSans).all()).results || [];
  if (!rows.length) return null;
  return { hostnames: rows.map((r) => r.hostname), batch_ids: rows.map((r) => r.id), roots: rows.map((r) => r.root) };
}

export function splitPems(pemText) {
  const out = [], re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let m; while ((m = re.exec(pemText || ''))) out.push(m[0] + '\n');
  return out;
}

export async function recordIssuance(db, plan, issued) {
  const id = (issued && issued.issuedAt) || new Date().toISOString();
  const pems = splitPems(issued.certPem || '');
  const leaf = pems[0] || issued.certPem;
  const rest = issued.chainPems && issued.chainPems.length ? issued.chainPems : pems.slice(1);
  await db.prepare(
    `INSERT INTO ct_certs (id, issued_at, hostnames_json, certificate_pem, chain_pems_json, scts_json)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(id, id, JSON.stringify(plan.hostnames), leaf, JSON.stringify(rest || []), JSON.stringify(issued.scts || [])).run();
  for (const bid of plan.batch_ids) {
    await db.prepare('UPDATE ct_batches SET published = 1, cert_id = ? WHERE id = ?').bind(id, bid).run();
  }
  await metaSet(db, 'last_anchor_at', id);
  return { id, issued_at: id, hostnames: plan.hostnames };
}

/* --- compact DER + PKCS#10 CSR (ECDSA P-256) --- */
function derLen(n) { if (n < 0x80) return Uint8Array.of(n); const b = []; while (n > 0) { b.unshift(n & 255); n = Math.floor(n / 256); } return Uint8Array.of(0x80 | b.length, ...b); }
function derEnc(tag, content) { return concat(Uint8Array.of(tag), derLen(content.length), content); }
function derSeq(...items) { return derEnc(0x30, concat(...items)); }
function derIntBytes(b) { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.subarray(i); if (b[0] & 0x80) b = concat(Uint8Array.of(0), b); return derEnc(0x02, b); }
function derOidEnc(str) {
  const p = str.split('.').map((x) => BigInt(x)); const out = [Number(p[0] * 40n + p[1])];
  for (let i = 2; i < p.length; i++) { let v = p[i]; const t = [Number(v & 0x7fn)]; v >>= 7n; while (v > 0n) { t.unshift(Number(v & 0x7fn) | 0x80); v >>= 7n; } out.push(...t); }
  return derEnc(0x06, Uint8Array.from(out));
}
function ecdsaRawToDer(sig) { return derSeq(derIntBytes(sig.subarray(0, 32)), derIntBytes(sig.subarray(32, 64))); }

export async function buildEcdsaCsr(hostnames, keyPair) {
  if (!hostnames.length) throw new Error('CSR needs at least one hostname');
  const kp = keyPair || await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const cn = hostnames[0];
  const subject = derSeq(derEnc(0x31, derSeq(derOidEnc('2.5.4.3'), derEnc(0x0c, utf8(cn)))));
  const generalNames = derSeq(...hostnames.map((h) => derEnc(0x82, utf8(h))));
  const sanExt = derSeq(derOidEnc('2.5.29.17'), derEnc(0x04, generalNames));
  const extensions = derSeq(sanExt);
  const attributes = derEnc(0xA0, derSeq(derOidEnc('1.2.840.113549.1.9.14'), derEnc(0x31, extensions)));
  const info = derSeq(derEnc(0x02, Uint8Array.of(0)), subject, spki, attributes);
  const sigRaw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, info));
  const csrDer = derSeq(info, derSeq(derOidEnc('1.2.840.10045.4.3.2')), derEnc(0x03, concat(Uint8Array.of(0), ecdsaRawToDer(sigRaw))));
  const b64 = toB64(csrDer).replace(/(.{64})/g, '$1\n').replace(/\n$/,'');
  const pem = '-----BEGIN CERTIFICATE REQUEST-----\n' + b64 + '\n-----END CERTIFICATE REQUEST-----\n';
  return { der: csrDer, pem, keyPair: kp };
}

/* --- Cloudflare DNS (strictly scoped to allowed ACME TXT names) --- */
export async function cloudflareSetTxt(env, name, content) {
  const fqdn = assertAllowedAcmeTxtName(name);
  if (!env.CF_DNS_TOKEN) throw new Error('CF_DNS_TOKEN is not configured');
  if (!env.CF_ZONE_ID) throw new Error('CF_ZONE_ID is not configured');
  await cloudflareClearTxt(env, fqdn);
  const r = await fetch(`https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records`, {
    method: 'POST',
    headers: { authorization: 'Bearer ' + env.CF_DNS_TOKEN, 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'TXT', name: fqdn, content, ttl: 60, comment: 'lightdrawer ct dns-01 temporary' }),
    signal: AbortSignal.timeout(15000),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.success === false) throw new Error('Cloudflare DNS create failed: ' + (j.errors && j.errors[0] && j.errors[0].message || r.status));
  return j.result && j.result.id;
}

export async function cloudflareClearTxt(env, name) {
  const fqdn = assertAllowedAcmeTxtName(name);
  if (!env.CF_DNS_TOKEN) throw new Error('CF_DNS_TOKEN is not configured');
  if (!env.CF_ZONE_ID) throw new Error('CF_ZONE_ID is not configured');
  const url = `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records?type=TXT&name=${encodeURIComponent(fqdn)}`;
  const r = await fetch(url, { headers: { authorization: 'Bearer ' + env.CF_DNS_TOKEN }, signal: AbortSignal.timeout(15000) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.success === false) throw new Error('Cloudflare DNS list failed: ' + (j.errors && j.errors[0] && j.errors[0].message || r.status));
  for (const rec of j.result || []) {
    if (String(rec.type).toUpperCase() !== 'TXT') continue;
    assertAllowedAcmeTxtName(rec.name);
    const d = await fetch(`https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records/${rec.id}`, {
      method: 'DELETE',
      headers: { authorization: 'Bearer ' + env.CF_DNS_TOKEN },
      signal: AbortSignal.timeout(15000),
    });
    if (!d.ok) throw new Error('Cloudflare DNS delete failed: HTTP ' + d.status);
  }
}

/* --- ACME (RFC 8555) two-phase DNS-01 --- */
async function importAccountKey(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
}
async function loadOrCreateAccount(db, directoryUrl) {
  const key = acmeAccountMetaKey(directoryUrl);
  const raw = await metaGet(db, key);
  if (raw) {
    try {
      const saved = JSON.parse(raw);
      if (saved.directoryUrl === directoryUrl && saved.jwk && saved.jwk.d) {
        const privateKey = await importAccountKey(saved.jwk);
        return { kid: saved.kid || null, jwk: saved.jwk, privateKey };
      }
    } catch { /* recreate */ }
  }
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  await metaSet(db, key, JSON.stringify({ directoryUrl, kid: null, jwk }));
  return { kid: null, jwk, privateKey: kp.privateKey };
}
async function saveAccountKid(db, directoryUrl, jwk, kid) {
  await metaSet(db, acmeAccountMetaKey(directoryUrl), JSON.stringify({ directoryUrl, kid, jwk }));
}

function publicJwk(jwk) { return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }; }

export function createAcmeClient({ directoryUrl, jwk, privateKey, fetchFn, env }) {
  assertAcmeDirectoryAllowed(directoryUrl, env);
  const fetchImpl = fetchFn || fetch;
  const pub = publicJwk(jwk);
  let kid = null, nonce = null, directory = null;

  async function signedPost(url, payload, useJwk) {
    if (!nonce) throw new Error('ACME nonce missing');
    const protectedHeader = useJwk ? { alg: 'ES256', nonce, url, jwk: pub } : { alg: 'ES256', nonce, url, kid };
    const prot = b64urlJson(protectedHeader);
    const pay = payload === undefined ? '' : b64urlJson(payload);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, utf8(prot + '.' + pay)));
    const body = JSON.stringify({ protected: prot, payload: pay, signature: b64url(sig) });
    const r = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/jose+json' }, body, signal: AbortSignal.timeout(20000) });
    nonce = r.headers.get('Replay-Nonce') || nonce;
    return r;
  }

  async function init() {
    const dirR = await fetchImpl(directoryUrl, { signal: AbortSignal.timeout(15000) });
    directory = await dirR.json();
    if (!directory.newNonce || !directory.newAccount || !directory.newOrder) throw new Error('ACME directory missing endpoints');
    const n = await fetchImpl(directory.newNonce, { method: 'HEAD', signal: AbortSignal.timeout(15000) });
    nonce = n.headers.get('Replay-Nonce');
    if (!nonce) {
      const n2 = await fetchImpl(directory.newNonce, { signal: AbortSignal.timeout(15000) });
      nonce = n2.headers.get('Replay-Nonce');
    }
    if (!nonce) throw new Error('ACME directory did not issue a nonce');
    return directory;
  }

  return {
    get directory() { return directory; },
    setKid(value) { kid = value; },
    getKid() { return kid; },
    init,
    signedPost,
    async ensureAccount() {
      const acc = await signedPost(directory.newAccount, { termsOfServiceAgreed: true }, true);
      if (!(acc.status === 200 || acc.status === 201)) throw new Error('newAccount HTTP ' + acc.status + ' ' + (await acc.text()).slice(0, 240));
      kid = acc.headers.get('Location') || kid;
      return kid;
    },
    async thumbprint() { return b64url(await sha256(utf8(JSON.stringify(pub)))); },
  };
}

export async function acmePhase1(env, db, plan) {
  const cfg = ctConfigFromEnv(env);
  assertAcmeDirectoryAllowed(cfg.directory, env);
  const account = await loadOrCreateAccount(db, cfg.directory);
  const client = createAcmeClient({ directoryUrl: cfg.directory, jwk: account.jwk, privateKey: account.privateKey, env });
  if (account.kid) client.setKid(account.kid);
  await client.init();
  if (!client.getKid()) {
    const kid = await client.ensureAccount();
    await saveAccountKid(db, cfg.directory, account.jwk, kid);
  }
  const orderReq = await client.signedPost(client.directory.newOrder, { identifiers: plan.hostnames.map((h) => ({ type: 'dns', value: h })) }, false);
  if (orderReq.status !== 201 && orderReq.status !== 200) throw new Error('newOrder HTTP ' + orderReq.status + ' ' + (await orderReq.text()).slice(0, 240));
  const order = await orderReq.json();
  const orderUrl = orderReq.headers.get('Location');
  const thumb = await client.thumbprint();
  const authorizations = [];
  for (const authzUrl of order.authorizations || []) {
    const azR = await client.signedPost(authzUrl, undefined, false);
    const az = await azR.json();
    const hostname = az.identifier && az.identifier.value;
    const ch = (az.challenges || []).find((c) => c.type === 'dns-01');
    if (!ch) throw new Error('no dns-01 challenge for ' + hostname);
    const keyAuth = ch.token + '.' + thumb;
    const txt = b64url(await sha256(utf8(keyAuth)));
    const txtName = '_acme-challenge.' + hostname;
    assertAllowedAcmeTxtName(txtName);
    await cloudflareSetTxt(env, txtName, txt);
    // Do not notify Let's Encrypt yet. Phase 2 posts the challenge after the
    // TXT record has had time to reach Cloudflare's nameservers. Immediate
    // notification can lose a race with NXDOMAIN negative-cache.
    authorizations.push({ url: authzUrl, hostname, txtName, txtValue: txt, challengeUrl: ch.url, challengePosted: false });
  }
  const state = {
    phase: 'pending_validation',
    directoryUrl: cfg.directory,
    orderUrl,
    finalizeUrl: order.finalize,
    hostnames: plan.hostnames,
    batch_ids: plan.batch_ids,
    authorizations,
    started_at: new Date().toISOString(),
  };
  await metaSet(db, 'issuance', JSON.stringify(state));
  return state;
}

export async function acmePhase2(env, db, state) {
  const cfg = ctConfigFromEnv(env);
  const directoryUrl = state.directoryUrl || cfg.directory;
  assertAcmeDirectoryAllowed(directoryUrl, env);
  const account = await loadOrCreateAccount(db, directoryUrl);
  const client = createAcmeClient({ directoryUrl, jwk: account.jwk, privateKey: account.privateKey, env });
  if (account.kid) client.setKid(account.kid);
  await client.init();
  if (!client.getKid()) {
    const kid = await client.ensureAccount();
    await saveAccountKid(db, directoryUrl, account.jwk, kid);
  }
  let notified = false;
  for (const az of state.authorizations || []) {
    if (az.challengePosted || !az.challengeUrl) continue;
    const pr = await client.signedPost(az.challengeUrl, {}, false);
    if (!pr.ok && pr.status !== 200) throw new Error('challenge POST HTTP ' + pr.status + ' ' + (await pr.text()).slice(0, 240));
    az.challengePosted = true;
    notified = true;
  }
  if (notified) await metaSet(db, 'issuance', JSON.stringify(state));
  let pending = 0, invalid = [];
  for (const az of state.authorizations || []) {
    const poll = await client.signedPost(az.url, undefined, false);
    const body = await poll.json();
    if (body.status === 'valid') continue;
    if (body.status === 'invalid') invalid.push({ hostname: az.hostname, detail: body });
    else pending += 1;
  }
  if (invalid.length) {
    for (const az of state.authorizations || []) {
      try { await cloudflareClearTxt(env, az.txtName); } catch { /* still report */ }
    }
    await metaDel(db, 'issuance');
    throw new Error('ACME authorization invalid: ' + JSON.stringify(invalid).slice(0, 1500));
  }
  if (pending) return { waiting: true, pending, hostnames: state.hostnames };

  const csr = await buildEcdsaCsr(state.hostnames);
  const fin = await client.signedPost(state.finalizeUrl, { csr: b64url(csr.der) }, false);
  if (!fin.ok && fin.status !== 200) throw new Error('finalize HTTP ' + fin.status + ' ' + (await fin.text()).slice(0, 240));
  let order = await fin.json();
  const orderUrl = state.orderUrl;
  for (let i = 0; i < 8; i++) {
    if (order.status === 'valid' && order.certificate) break;
    if (order.status === 'invalid') throw new Error('order invalid: ' + JSON.stringify(order).slice(0, 400));
    await new Promise((res) => setTimeout(res, 1500));
    const poll = await client.signedPost(orderUrl, undefined, false);
    order = await poll.json();
  }
  if (!order.certificate) return { waiting: true, pending: 1, status: order.status, hostnames: state.hostnames };
  const certR = await client.signedPost(order.certificate, undefined, false);
  const pem = await certR.text();
  if (!/BEGIN CERTIFICATE/.test(pem)) throw new Error('ACME certificate response was not a PEM chain');
  const issued = {
    certPem: pem,
    chainPems: splitPems(pem).slice(1),
    scts: [],
    issuedAt: new Date().toISOString(),
    method: isProductionDirectory(directoryUrl) ? 'acme-dns-01' : 'acme-dns-01-staging',
  };
  const cert = await recordIssuance(db, { hostnames: state.hostnames, batch_ids: state.batch_ids }, issued);
  for (const az of state.authorizations || []) {
    try { await cloudflareClearTxt(env, az.txtName); } catch (e) { issued.clearError = String(e.message || e); }
  }
  await metaDel(db, 'issuance');
  return { issued: true, cert_id: cert.id, hostnames: state.hostnames, method: issued.method, clearError: issued.clearError || null };
}

export async function clearIssuanceError(db, issuance) {
  if (issuance && issuance.issued === true) await metaDel(db, 'last_error');
}

export async function runCtTick(env, opts = {}) {
  const force = !!opts.force;
  const summary = { ok: true, force, closed: [], issuance: null, skipped: null, error: null };
  if (!env.CT_DB) {
    summary.ok = false;
    summary.error = 'CT_DB is not bound';
    return summary;
  }
  const db = env.CT_DB;
  let cfg;
  try { cfg = ctConfigFromEnv(env); }
  catch (e) {
    summary.ok = false;
    summary.error = e.message;
    return summary;
  }
  try {
    summary.closed = await closeDueSubBatches(db, new Date(), {
      includeOpen: force || !!opts.includeOpen,
      subBatchMs: cfg.subBatchMs,
      hostnameSuffix: cfg.hostnameSuffix,
    });
    const raw = await metaGet(db, 'issuance');
    if (raw) {
      const state = JSON.parse(raw);
      if (state.directoryUrl && state.directoryUrl !== cfg.directory) {
        for (const az of state.authorizations || []) {
          try { await cloudflareClearTxt(env, az.txtName); } catch { /* leftover challenge */ }
        }
        await metaDel(db, 'issuance');
      } else {
        if (!env.CF_DNS_TOKEN) {
          summary.skipped = 'issuance in progress but CF_DNS_TOKEN is not configured';
          return summary;
        }
        summary.issuance = await acmePhase2(env, db, state);
        await clearIssuanceError(db, summary.issuance);
        return summary;
      }
    }
    const plan = await planAnchor(db, new Date(), { force, anchorEveryMs: cfg.anchorEveryMs, maxSans: cfg.maxSans });
    if (!plan) {
      summary.issuance = { skipped: true, reason: 'no unpublished batches or interval not elapsed' };
      return summary;
    }
    if (!env.CF_DNS_TOKEN) {
      summary.skipped = 'CF_DNS_TOKEN is not configured; batches are queued until a DNS-edit token is set';
      summary.issuance = { skipped: true, planned_hostnames: plan.hostnames };
      return summary;
    }
    await metaSet(db, 'last_attempt_at', new Date().toISOString());
    summary.issuance = { started: true, ...(await acmePhase1(env, db, plan)) };
    return summary;
  } catch (e) {
    summary.ok = false;
    summary.error = e.message || String(e);
    try { await metaSet(db, 'last_error', JSON.stringify({ at: new Date().toISOString(), error: summary.error })); } catch { /* ignore */ }
    try { await metaSet(db, 'last_attempt_at', new Date().toISOString()); } catch { /* ignore */ }
    return summary;
  }
}
