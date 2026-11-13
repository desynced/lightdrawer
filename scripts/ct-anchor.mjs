#!/usr/bin/env node
// Certificate-log stamp runner (prototype). Collects SHA-256 fingerprints into
// time-window sub-batches, then issues one ACME certificate covering up to 100
// batch-root hostnames. Default: close sub-batches every 15 minutes and request
// a certificate every 6 hours (~4/day, ~28/week) so we stay under Let's Encrypt's
// 50 new certificates per registered domain per 7 days, with retry headroom.
//
// This script is the working prototype. A Cloudflare Worker cron can run the
// same functions later (see README / HOW-IT-WORKS.md). It does not talk to
// Cloudflare DNS or Let's Encrypt production unless you pass flags that we
// still refuse for production.
//
// Usage:
//   node scripts/ct-anchor.mjs submit <digest> [--state FILE] [--now ISO]
//   node scripts/ct-anchor.mjs close-sub-batch [--state FILE] [--now ISO] [--include-open]
//   node scripts/ct-anchor.mjs issue [--state FILE] [--now ISO] [--issuer mock] [--force]
//   node scripts/ct-anchor.mjs upgrade <digest> [--state FILE]
//   node scripts/ct-anchor.mjs status [--state FILE]
//   node scripts/ct-anchor.mjs refuse-prod-check   # prints and exits 0 if production URLs are blocked
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const corePath = join(root, 'build/core.js');
if (!existsSync(corePath)) {
  console.error('build/core.js missing; run `npm run build` first');
  process.exit(2);
}
const coreSrc = readFileSync(corePath, 'utf8');
const names = [
  'CT_DEFAULTS', 'ctConfigNormalize', 'ctWeeklyCertEstimate', 'ctRootToHostname', 'ctHostnameToRoot',
  'ctMerkleBuild', 'ctMerkleVerify', 'ctNewState', 'ctSubmit', 'ctCloseDueSubBatches', 'ctPlanAnchor',
  'ctRecordIssuance', 'ctPendingEntry', 'ctUpgradeFromState', 'ctVerify', 'toHex', 'fromHex', 'utf8',
  'sha256', 'toB64', 'fromB64', 'bytesEq', 'x509Parse', 'x509SANs', 'pemToDer',
];
const L = new Function(coreSrc + `\nreturn { ${names.join(', ')} };`)();

const PRODUCTION = new Set(L.CT_DEFAULTS.acmeProductionDirectories);
function assertNotProductionDirectory(url) {
  const u = String(url || '').replace(/\/+$/, '');
  if (PRODUCTION.has(u) || PRODUCTION.has(u + '/directory') || /acme-v0[12]\.api\.letsencrypt\.org/i.test(u)) {
    throw new Error('Refusing to use the Let\'s Encrypt PRODUCTION ACME directory. This prototype only allows staging, Pebble, or a mock. Directory was: ' + url);
  }
}

export function loadState(path, cfg) {
  if (path && existsSync(path)) {
    const s = JSON.parse(readFileSync(path, 'utf8'));
    s.config = L.ctConfigNormalize(Object.assign({}, s.config, cfg || {})).config;
    return s;
  }
  return L.ctNewState(cfg);
}
export function saveState(path, state) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(state, null, 2) + '\n');
}

export function mockCertTempSuffix() {
  return crypto.randomUUID();
}

export async function mockIssueCertificate(hostnames) {
  if (!hostnames.length) throw new Error('no hostnames to certify');
  const dir = join(tmpdir(), 'lightdrawer-ct-' + Date.now() + '-' + mockCertTempSuffix());
  mkdirSync(dir, { recursive: true });
  const key = join(dir, 'key.pem'), cert = join(dir, 'cert.pem');
  const san = hostnames.map((h) => 'DNS:' + h).join(',');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', key, '-out', cert, '-days', '1',
    '-subj', '/CN=ct.lightdrawer.org',
    '-addext', 'subjectAltName=' + san,
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  const certPem = readFileSync(cert, 'utf8');
  return { certPem, chainPems: [], scts: [], issuedAt: new Date().toISOString(), method: 'openssl-self-signed-mock' };
}

/* Compact ACME client (RFC 8555 DNS-01). fetch and setTxt are injectable. */
function b64url(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return L.toB64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function b64urlJson(obj) { return b64url(L.utf8(JSON.stringify(obj))); }

export async function acmeIssue({ directoryUrl, hostnames, fetchFn, setTxt, clearTxt, accountKey }) {
  assertNotProductionDirectory(directoryUrl);
  const fetchImpl = fetchFn || fetch;
  const dir = await (await fetchImpl(directoryUrl)).json();
  if (!dir.newNonce || !dir.newAccount || !dir.newOrder) throw new Error('ACME directory missing endpoints');
  const kp = accountKey || await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const pub = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  const thumb = b64url(await L.sha256(L.utf8(JSON.stringify(pub))));
  let kid = null, nonce = (await fetchImpl(dir.newNonce)).headers.get('Replay-Nonce');

  async function signedPost(url, payload, useJwk) {
    const protectedHeader = useJwk
      ? { alg: 'ES256', nonce, url, jwk: pub }
      : { alg: 'ES256', nonce, url, kid };
    const prot = b64urlJson(protectedHeader);
    const pay = payload === undefined ? '' : b64urlJson(payload);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, L.utf8(prot + '.' + pay)));
    const body = JSON.stringify({ protected: prot, payload: pay, signature: b64url(sig) });
    const r = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/jose+json' }, body });
    nonce = r.headers.get('Replay-Nonce') || nonce;
    return r;
  }

  const acc = await signedPost(dir.newAccount, { termsOfServiceAgreed: true }, true);
  if (!(acc.status === 200 || acc.status === 201)) throw new Error('newAccount HTTP ' + acc.status + ' ' + (await acc.text()).slice(0, 200));
  kid = acc.headers.get('Location');
  const orderReq = await signedPost(dir.newOrder, { identifiers: hostnames.map((h) => ({ type: 'dns', value: h })) }, false);
  if (orderReq.status !== 201 && orderReq.status !== 200) throw new Error('newOrder HTTP ' + orderReq.status);
  let order = await orderReq.json();
  const orderUrl = orderReq.headers.get('Location');
  for (const authzUrl of order.authorizations || []) {
    const azR = await signedPost(authzUrl, undefined, false);
    const az = await azR.json();
    const ch = (az.challenges || []).find((c) => c.type === 'dns-01');
    if (!ch) throw new Error('no dns-01 challenge for ' + (az.identifier && az.identifier.value));
    const keyAuth = ch.token + '.' + thumb;
    const txt = b64url(await L.sha256(L.utf8(keyAuth)));
    const name = '_acme-challenge.' + az.identifier.value;
    await setTxt(name, txt);
    const pr = await signedPost(ch.url, {}, false);
    if (!pr.ok && pr.status !== 200) throw new Error('challenge POST HTTP ' + pr.status);
    for (let i = 0; i < 20; i++) {
      const poll = await signedPost(authzUrl, undefined, false);
      const body = await poll.json();
      if (body.status === 'valid') break;
      if (body.status === 'invalid') throw new Error('authorization invalid: ' + JSON.stringify(body));
      await new Promise((res) => setTimeout(res, 50));
    }
    if (clearTxt) await clearTxt(name);
  }
  // CSR: the mock ACME server accepts a placeholder; a production Worker would
  // build a real PKCS#10 CSR with WebCrypto (see comments in README).
  const fin = await signedPost(order.finalize, { csr: b64url(L.utf8(hostnames.join(','))) }, false);
  if (!fin.ok && fin.status !== 200) throw new Error('finalize HTTP ' + fin.status);
  for (let i = 0; i < 20; i++) {
    const poll = await signedPost(orderUrl || dir.newOrder, undefined, false);
    order = await poll.json();
    if (order.status === 'valid' && order.certificate) break;
    if (order.status === 'invalid') throw new Error('order invalid');
    await new Promise((res) => setTimeout(res, 50));
  }
  if (!order.certificate) throw new Error('order never produced a certificate URL');
  const certR = await signedPost(order.certificate, undefined, false);
  const pem = await certR.text();
  return { certPem: pem, chainPems: [], scts: [], issuedAt: new Date().toISOString(), method: 'acme-dns-01' };
}

/* In-process ACME + DNS mock for tests. Does not bind ports or touch real DNS. */
export function createMockAcmeDns(hostnamesExpected) {
  const txt = new Map();
  let nonceN = 1;
  const orders = new Map(), authz = new Map();
  let orderN = 0, accN = 0;
  const directoryUrl = 'https://acme.mock.test/directory';
  async function fetchFn(url, init = {}) {
    const u = String(url);
    const json = (obj, status = 200, headers = {}) => new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json', 'replay-nonce': 'n' + (nonceN++), ...headers } });
    if (u === directoryUrl && (!init.method || init.method === 'GET')) {
      return json({ newNonce: 'https://acme.mock.test/new-nonce', newAccount: 'https://acme.mock.test/new-account', newOrder: 'https://acme.mock.test/new-order' });
    }
    if (u === 'https://acme.mock.test/new-nonce') return new Response('', { headers: { 'replay-nonce': 'n' + (nonceN++) } });
    const method = init.method || 'GET';
    if (u === 'https://acme.mock.test/new-account' && method === 'POST') {
      return json({ status: 'valid' }, 201, { location: 'https://acme.mock.test/acct/' + (++accN) });
    }
    if (u === 'https://acme.mock.test/new-order' && method === 'POST') {
      const jws = JSON.parse(init.body);
      const payload = JSON.parse(Buffer.from(jws.payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
      const id = ++orderN;
      const authzUrls = [];
      for (const ident of payload.identifiers) {
        const a = 'https://acme.mock.test/authz/' + id + '/' + ident.value;
        authzUrls.push(a);
        authz.set(a, { identifier: ident, status: 'pending', challenges: [{ type: 'dns-01', url: a + '/dns', token: 'token-' + id + '-' + ident.value, status: 'pending' }], _txtName: '_acme-challenge.' + ident.value });
      }
      const order = { status: 'pending', authorizations: authzUrls, finalize: 'https://acme.mock.test/finalize/' + id, identifiers: payload.identifiers };
      orders.set('https://acme.mock.test/order/' + id, order);
      orders.set('https://acme.mock.test/finalize/' + id, order);
      return json(order, 201, { location: 'https://acme.mock.test/order/' + id });
    }
    if (authz.has(u) && method === 'POST') return json(authz.get(u));
    if (u.endsWith('/dns') && method === 'POST') {
      const azUrl = u.slice(0, -4);
      const az = authz.get(azUrl);
      const recs = txt.get(az._txtName) || [];
      if (!recs.length) return json({ status: 'invalid', error: 'no TXT' }, 200);
      az.status = 'valid';
      az.challenges[0].status = 'valid';
      return json(az.challenges[0]);
    }
    if (u.startsWith('https://acme.mock.test/finalize/') && method === 'POST') {
      const orderUrl = u.replace('/finalize/', '/order/');
      const order = orders.get(orderUrl);
      const issued = await mockIssueCertificate(order.identifiers.map((i) => i.value));
      order.status = 'valid';
      order.certificate = 'https://acme.mock.test/cert/' + orderUrl.split('/').pop();
      order._pem = issued.certPem;
      return json(order);
    }
    if (u.startsWith('https://acme.mock.test/order/') && method === 'POST') return json(orders.get(u));
    if (u.startsWith('https://acme.mock.test/cert/') && method === 'POST') {
      const id = u.split('/').pop();
      const order = orders.get('https://acme.mock.test/order/' + id);
      return new Response(order._pem, { headers: { 'content-type': 'application/pem-certificate-chain', 'replay-nonce': 'n' + (nonceN++) } });
    }
    return new Response('not found ' + u, { status: 404 });
  }
  return {
    directoryUrl,
    fetchFn,
    setTxt: async (name, value) => { const k = name.toLowerCase(); txt.set(k, (txt.get(k) || []).concat(value)); },
    clearTxt: async (name) => { txt.delete(name.toLowerCase()); },
    txt,
  };
}

function defaultStatePath() { return join(root, 'build/ct-state.json'); }

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
      args[k] = v;
    } else args._.push(a);
  }
  return args;
}

export async function runCli(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const cmd = args._[0];
  const statePath = resolve(String(args.state || defaultStatePath()));
  const now = args.now ? new Date(args.now) : new Date();
  if (cmd === 'refuse-prod-check') {
    let blocked = false;
    try { assertNotProductionDirectory('https://acme-v02.api.letsencrypt.org/directory'); }
    catch (e) { blocked = true; }
    if (!blocked) throw new Error('production directory was not blocked');
    console.log('ok: production ACME directory is refused');
    return 0;
  }
  if (!cmd || cmd === 'help' || cmd === '--help') {
    console.log('ct-anchor: submit | close-sub-batch | issue | upgrade | status | refuse-prod-check');
    return 0;
  }
  const state = loadState(statePath, {
    subBatchMs: args['sub-batch-ms'] ? Number(args['sub-batch-ms']) : undefined,
    anchorEveryMs: args['anchor-every-ms'] ? Number(args['anchor-every-ms']) : undefined,
    hostnameSuffix: args.suffix || undefined,
  });
  if (cmd === 'submit') {
    const digest = args._[1];
    const r = L.ctSubmit(state, digest, now);
    saveState(statePath, state);
    console.log(JSON.stringify(r));
    return 0;
  }
  if (cmd === 'close-sub-batch') {
    const closed = await L.ctCloseDueSubBatches(state, now, { includeOpen: !!args['include-open'] });
    saveState(statePath, state);
    console.log(JSON.stringify({ closed: closed.map((b) => ({ id: b.id, root: b.root, hostname: b.hostname, tree_size: b.tree_size })) }, null, 2));
    return 0;
  }
  if (cmd === 'issue') {
    const plan = L.ctPlanAnchor(state, now, { force: !!args.force });
    if (!plan) { console.log(JSON.stringify({ skipped: true })); return 0; }
    const issuer = String(args.issuer || 'mock');
    let issued;
    if (issuer === 'mock') issued = await mockIssueCertificate(plan.hostnames);
    else if (issuer === 'mock-acme') {
      const mock = createMockAcmeDns(plan.hostnames);
      issued = await acmeIssue({ directoryUrl: mock.directoryUrl, hostnames: plan.hostnames, fetchFn: mock.fetchFn, setTxt: mock.setTxt, clearTxt: mock.clearTxt });
    } else if (issuer === 'acme') {
      assertNotProductionDirectory(args.directory || L.CT_DEFAULTS.acmeStagingDirectory);
      throw new Error('Live ACME issuance is disabled in this prototype because it would require creating DNS TXT records. Use --issuer mock or --issuer mock-acme.');
    } else throw new Error('unknown --issuer ' + issuer);
    const cert = L.ctRecordIssuance(state, plan, issued);
    saveState(statePath, state);
    console.log(JSON.stringify({ issued: true, hostnames: plan.hostnames, method: issued.method, issued_at: cert.issued_at }, null, 2));
    return 0;
  }
  if (cmd === 'upgrade') {
    const digest = args._[1];
    const entry = L.ctUpgradeFromState(state, digest);
    if (!entry) { console.log(JSON.stringify({ pending: true, found: false })); return 0; }
    console.log(JSON.stringify(entry, null, 2));
    return 0;
  }
  if (cmd === 'status') {
    const cfg = L.ctConfigNormalize(state.config);
    console.log(JSON.stringify({
      pending: state.pending.length,
      sub_batches: state.sub_batches.map((b) => ({ id: b.id, published: b.published, size: b.tree_size, hostname: b.hostname })),
      certs: state.certs.length,
      last_anchor_at: state.last_anchor_at,
      weekly_certs_estimate: cfg.weekly,
      sans_per_anchor: cfg.sansPerAnchor,
      warnings: cfg.warnings,
    }, null, 2));
    return 0;
  }
  throw new Error('unknown command ' + cmd);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) runCli().then((code) => process.exit(code || 0)).catch((e) => { console.error(e.message || e); process.exit(1); });
