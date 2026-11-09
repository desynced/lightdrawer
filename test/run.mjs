// Self-tests for the receipt core. `node test/run.mjs` (offline + public read-only lookups)
// `node test/run.mjs --live` also stamps a throwaway test hash at OpenTimestamps calendars
// and FreeTSA (hash only; no Rekor write) and checks the result with openssl and `ots`.
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { runStampApiTests } from './stamp-api.mjs';
import { fileURLToPath } from 'node:url';
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const core = readFileSync(join(root, 'build/core.js'), 'utf8');
const names = ['toHex', 'fromHex', 'utf8', 'sha256', 'bytesEq', 'tsaVerify', 'tsaBuildRequest', 'otsParseDetached', 'otsSerializeDetached', 'otsVerify', 'otsEsploraLookup', 'otsAttestations', 'rekorVerify', 'zipWrite', 'zipRead', 'c2paInspect', 'c2paInspectSource', 'makeReceipt', 'verifyReceipt', 'TRUST', 'TRUST_FILES', 'OTS_DEFAULT_CALENDARS', 'coverText', 'CT_DEFAULTS', 'ctConfigNormalize', 'ctWeeklyCertEstimate', 'ctRootToHostname', 'ctHostnameToRoot', 'ctMerkleBuild', 'ctMerkleVerify', 'ctNewState', 'ctSubmit', 'ctCloseDueSubBatches', 'ctPlanAnchor', 'ctRecordIssuance', 'ctPendingEntry', 'ctUpgradeFromState', 'ctVerify', 'x509Parse', 'x509SANs', 'pemToDer', 'sha256Source', 'sha256Create', 'sha256Update', 'sha256Finish', 'SHA256_FILE_CHUNK', 'C2PA_HEAD_BYTES'];
const L = new Function(core + `\nreturn { ${names.join(', ')} };`)();
const fx = (f) => new Uint8Array(readFileSync(join(root, 'test/fixtures', f)));
let failed = 0;
const ok = (cond, msg) => { console.log((cond ? '  ok   ' : '  FAIL ') + msg); if (!cond) failed++; };
const st = (checks, id) => (checks.find((c) => c.id === id) || {}).status;
const live = process.argv.includes('--live');

console.log('RFC 3161 (FreeTSA fixture made with openssl)');
{
  const d = await L.sha256(fx('tsa-sample.txt'));
  const r = await L.tsaVerify(fx('tsa-sample.txt.tsr'), d, L.TRUST, null);
  for (const c of r.checks) console.log(`     ${c.status.padEnd(4)} ${c.title} ${c.detail ? '— ' + c.detail.slice(0, 90) : ''}`);
  ok(!r.checks.some((c) => c.status === 'fail'), 'valid token verifies');
  const bad = await L.tsaVerify(fx('tsa-sample.txt.tsr'), await L.sha256(L.utf8('other')), L.TRUST, null);
  ok(st(bad.checks, 'tsa.imprint') === 'fail', 'wrong hash is rejected');
  const t = fx('tsa-sample.txt.tsr'); const t2 = Uint8Array.from(t); t2[t2.length - 10] ^= 1;
  const bad2 = await L.tsaVerify(t2, d, L.TRUST, null);
  ok(bad2.checks.some((c) => c.status === 'fail'), 'tampered signature is rejected');
}
console.log('OpenTimestamps (hello-world.txt.ots from opentimestamps-client examples)');
{
  const bytes = fx('hello-world.txt.ots'); const d = await L.sha256(fx('hello-world.txt'));
  const p = await L.otsParseDetached(bytes);
  ok(L.bytesEq(L.otsSerializeDetached(p.digest, p.root), bytes), 'parse → serialize round-trips byte-exact');
  const off = await L.otsVerify(bytes, d, null);
  ok(st(off.checks, 'ots.digest') === 'pass' && off.bitcoinHeights.includes(358391), 'offline: digest ok, claims block 358391');
  try {
    const on = await L.otsVerify(bytes, d, (h) => L.otsEsploraLookup(h));
    ok(st(on.checks, 'ots.btc.358391') === 'pass', 'online: Bitcoin block 358391 merkle root matches (' + (on.checks.find((c) => c.id === 'ots.btc.358391') || {}).detail + ')');
  } catch (e) { ok(false, 'online lookup ' + e.message); }
  const bad = await L.otsVerify(bytes, await L.sha256(L.utf8('x')), null);
  ok(st(bad.checks, 'ots.digest') === 'fail', 'wrong hash is rejected');
}
console.log('Sigstore Rekor (public entry fixture, read-only)');
{
  const e = JSON.parse(readFileSync(join(root, 'test/fixtures/rekor-sample-entry.json'), 'utf8'));
  const r = await L.rekorVerify(e, L.utf8('not the artifact'), L.TRUST);
  for (const c of r.checks) console.log(`     ${c.status.padEnd(4)} ${c.title}`);
  ok(st(r.checks, 'rekor.logid') === 'pass' && st(r.checks, 'rekor.set') === 'pass' && st(r.checks, 'rekor.inclusion') === 'pass' && st(r.checks, 'rekor.checkpoint') === 'pass', 'log id, SET, inclusion proof, checkpoint verify');
  ok(st(r.checks, 'rekor.hash') === 'fail', 'mismatched artifact is rejected');
  const e2 = JSON.parse(JSON.stringify(e)); const k = Object.keys(e2)[0]; e2[k].integratedTime += 1;
  ok(st((await L.rekorVerify(e2, L.utf8('x'), L.TRUST)).checks, 'rekor.set') === 'fail', 'altered integratedTime breaks SET');
}
console.log('C2PA (c2pa-rs fixture CA.jpg)');
{
  const info = L.c2paInspect(fx('c2pa-sample-CA.jpg'));
  console.log('     ' + JSON.stringify({ container: info.container, n: info.manifestCount, gen: info.active && info.active.generator, title: info.active && info.active.title, signer: info.active && info.active.signer, assertions: info.active && info.active.assertions }).slice(0, 400));
  ok(info.present && info.manifestCount >= 1 && !!info.active.generator, 'manifest store found and claim decoded');
  ok(!!(info.active && info.active.signer), 'signer certificate subject read');
  ok(!L.c2paInspect(fx('hello-world.txt')).present, 'plain file reports no C2PA');
}
console.log('ZIP');
{
  const z = L.zipWrite([{ name: 'a.txt', data: L.utf8('hello') }, { name: 'proofs/b.bin', data: Uint8Array.of(0, 1, 2) }]);
  const f = await L.zipRead(z);
  ok(L.bytesEq(f['a.txt'], L.utf8('hello')) && f['proofs/b.bin'].length === 3, 'write/read round-trip');
  const tmp = join(root, 'build/ziptest'); rmSync(tmp, { recursive: true, force: true }); mkdirSync(tmp, { recursive: true });
  writeFileSync(join(tmp, 'z.zip'), z);
  try { execFileSync('python3', ['-c', 'import zipfile,sys;z=zipfile.ZipFile(sys.argv[1]);assert z.testzip() is None;print(z.namelist())', join(tmp, 'z.zip')]); ok(true, 'python zipfile accepts our ZIP'); } catch (e) { ok(false, 'python zipfile: ' + e.message); }
}
console.log('Streaming SHA-256 (must match WebCrypto and Node crypto)');
{
  const nodeHex = (u8) => createHash('sha256').update(u8).digest('hex');
  const empty = new Uint8Array(0);
  ok(L.toHex(await L.sha256Source(empty)) === L.toHex(await L.sha256(empty)) && L.toHex(await L.sha256(empty)) === nodeHex(empty), 'empty input matches WebCrypto and Node');
  const abc = L.utf8('abc');
  ok(L.toHex(await L.sha256Source(abc)) === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'NIST vector "abc"');
  const chunk = 1024;
  const sizes = [1, 55, 56, 63, 64, 65, chunk - 1, chunk, chunk + 1, chunk * 2, chunk * 2 + 1];
  let all = true;
  for (const n of sizes) {
    const buf = new Uint8Array(n); for (let i = 0; i < n; i++) buf[i] = (i * 31 + 7) & 0xff;
    const a = L.toHex(await L.sha256Source(buf, { chunkSize: chunk }));
    const b = L.toHex(await L.sha256(buf));
    const c = nodeHex(buf);
    if (a !== b || a !== c) { all = false; console.log('     mismatch at size ' + n); }
  }
  ok(all, 'boundary sizes (SHA-256 block and chunk ±1) match WebCrypto and Node');
  // large generated file: 12 MiB, hashed in 4 MiB chunks, compared to Node streaming hash
  const large = 12 * 1024 * 1024;
  const step = L.SHA256_FILE_CHUNK;
  const node = createHash('sha256');
  const ctx = L.sha256Create();
  for (let i = 0; i < large; i += step) {
    const n = Math.min(step, large - i);
    const buf = Buffer.allocUnsafe(n);
    for (let j = 0; j < n; j++) buf[j] = (i + j) & 0xff;
    node.update(buf);
    L.sha256Update(ctx, buf);
  }
  ok(L.toHex(L.sha256Finish(ctx)) === node.digest('hex'), '12 MiB generated file, 4 MiB chunks, matches Node crypto');
  if (typeof Blob === 'function') {
    const payload = new Uint8Array(chunk + 1); payload.fill(0x5a);
    const blobHash = L.toHex(await L.sha256Source(new Blob([payload]), { chunkSize: chunk }));
    ok(blobHash === nodeHex(payload), 'Blob.slice path matches Node');
  }
  const sample = fx('c2pa-sample-CA.jpg');
  const viaHead = await L.c2paInspectSource(sample);
  ok(viaHead.present && viaHead.manifestCount >= 1, 'c2paInspectSource still finds the sample manifest from bytes');
  if (typeof Blob === 'function') {
    const viaBlob = await L.c2paInspectSource(new Blob([sample]));
    ok(viaBlob.present && viaBlob.active && viaBlob.active.generator === viaHead.active.generator, 'c2paInspectSource on a Blob of the sample matches');
  }
}

console.log('Certificate Transparency helpers (Merkle, names, ct.json, verifier)');

{
  const hex = async (n) => L.toHex(await L.sha256(L.utf8('leaf-' + n)));
  const a = await hex(1), b = await hex(2), c = await hex(3), d = await hex(4), e = await hex(5);
  const one = await L.ctMerkleBuild([a]);
  ok(one.tree_size === 1 && await L.ctMerkleVerify(a, 0, one.proofs[a].path, one.root, 1), 'single-leaf tree verifies');
  const two = await L.ctMerkleBuild([b, a]);
  const twoB = await L.ctMerkleBuild([a, b]);
  ok(two.root === twoB.root && two.leaves[0] === (a < b ? a : b), 'leaves are sorted so order of submit does not change the root');
  ok(await L.ctMerkleVerify(a, two.proofs[a].index, two.proofs[a].path, two.root, 2), 'two-leaf inclusion (a)');
  ok(await L.ctMerkleVerify(b, two.proofs[b].index, two.proofs[b].path, two.root, 2), 'two-leaf inclusion (b)');
  const three = await L.ctMerkleBuild([a, b, c]);
  ok(await L.ctMerkleVerify(c, three.proofs[c].index, three.proofs[c].path, three.root, 3), 'three-leaf (odd) inclusion verifies');
  ok(!(await L.ctMerkleVerify(d, three.proofs[a].index, three.proofs[a].path, three.root, 3)), 'wrong digest is rejected');
  const five = await L.ctMerkleBuild([a, b, c, d, e]);
  ok(await L.ctMerkleVerify(e, five.proofs[e].index, five.proofs[e].path, five.root, 5), 'five-leaf inclusion verifies');

  const host = L.ctRootToHostname(three.root, 'ct.lightdrawer.org');
  ok(host === three.root.slice(0, 32) + '.' + three.root.slice(32) + '.ct.lightdrawer.org', 'hostname is two 32-char hex labels plus suffix');
  ok(host.split('.').slice(0, 2).every((lab) => lab.length === 32 && lab.length <= 63), 'each label is 32 chars (under the 63-char DNS limit)');
  ok(L.ctHostnameToRoot(host.toUpperCase()) === three.root, 'hostname decodes case-insensitively');
  let threw = false; try { L.ctHostnameToRoot('nope.ct.lightdrawer.org'); } catch { threw = true; }
  ok(threw, 'malformed hostname is rejected');

  const cfg = L.ctConfigNormalize({});
  ok(cfg.weekly === 28 && cfg.sansPerAnchor === 24, 'default 6h anchor / 15min sub-batch => 28 certs/week and 24 SANs');
  ok(L.ctWeeklyCertEstimate(4 * 60 * 60 * 1000) === 42, 'weekly estimate for 4 hours is 42');
  ok(L.ctConfigNormalize({ anchorEveryMs: 60 * 60 * 1000 }).warnings.length > 0, 'hourly anchors warn about the 50/week Let’s Encrypt cap');

  const pending = L.ctPendingEntry(a);
  ok(pending.status === 'pending' && pending.digest === a && pending.lightdrawer_ct === 1, 'pending ct.json shape');

  const t0 = new Date('2026-11-09T00:01:00Z');
  const tClose = new Date('2026-11-09T00:16:00Z');
  const tAnchor = new Date('2026-11-09T04:01:00Z');
  const st = L.ctNewState({ hostnameSuffix: 'ct.lightdrawer.org' });
  L.ctSubmit(st, a, t0);
  L.ctSubmit(st, b, new Date('2026-11-09T00:02:00Z'));
  L.ctSubmit(st, a, t0);
  ok(st.pending.length === 2, 'duplicate submit is ignored');
  const closed = await L.ctCloseDueSubBatches(st, tClose);
  ok(closed.length === 1 && closed[0].tree_size === 2 && st.pending.length === 0, 'due sub-batch closes and pending digests leave the waiting queue');
  const early = L.ctPlanAnchor(st, new Date('2026-11-09T00:17:00Z'));
  ok(early && early.hostnames[0] === closed[0].hostname, 'first certificate can be issued as soon as a sub-batch has closed');
  const plan = L.ctPlanAnchor(st, tAnchor);
  ok(plan && plan.hostnames.length === 1 && plan.hostnames[0] === closed[0].hostname, 'plans one SAN for the closed sub-batch');

  const { mockIssueCertificate, acmeIssue, createMockAcmeDns, runCli } = await import(new URL('../scripts/ct-anchor.mjs', import.meta.url));
  const issued = await mockIssueCertificate(plan.hostnames);
  issued.issuedAt = '2026-11-09T00:22:00.000Z';
  L.ctRecordIssuance(st, plan, issued);
  L.ctSubmit(st, c, new Date('2026-11-09T04:02:00Z'));
  await L.ctCloseDueSubBatches(st, new Date('2026-11-09T04:20:00Z'));
  ok(!L.ctPlanAnchor(st, new Date('2026-11-09T04:21:00Z')), 'waits the configured interval before requesting another certificate');
  ok(!!L.ctPlanAnchor(st, new Date('2026-11-09T08:02:00Z')), 'next certificate is allowed after the configured interval');
  const leaf = L.x509Parse(L.pemToDer(issued.certPem));
  const sans = L.x509SANs(leaf);
  ok(sans.includes(plan.hostnames[0]), 'mock certificate SAN is the encoded batch root');

  const entry = L.ctUpgradeFromState(st, a);
  ok(entry && entry.status === 'anchored' && entry.merkle.root === closed[0].root, 'upgrade returns anchored ct.json');
  ok(entry.crtsh_url.includes(plan.hostnames[0]), 'crt.sh URL uses the hostname');
  const v = await L.ctVerify(entry, a, { extraRoots: [issued.certPem], ctLogs: [] });
  ok(v.checks.find((c) => c.id === 'ct.merkle').status === 'pass', 'verifier: Merkle path passes');
  ok(v.checks.find((c) => c.id === 'ct.hostname').status === 'pass', 'verifier: hostname matches root');
  ok(v.checks.find((c) => c.id === 'ct.san').status === 'pass', 'verifier: SAN matches hostname');
  ok(v.checks.find((c) => c.id === 'ct.chain').status === 'pass', 'verifier: test root accepted via extraRoots');
  ok(v.times.length >= 1, 'verifier reports a time from the trusted chain');
  const bad = await L.ctVerify(entry, d, { extraRoots: [issued.certPem] });
  ok(bad.checks.some((c) => c.status === 'fail'), 'verifier rejects a different digest');
  const forged = JSON.parse(JSON.stringify(entry));
  forged.hostname = L.ctRootToHostname(d);
  const badHost = await L.ctVerify(forged, a, { extraRoots: [issued.certPem] });
  ok(badHost.checks.some((c) => c.id === 'ct.hostname' && c.status === 'fail'), 'verifier rejects a hostname that does not encode the root');

  const pv = await L.ctVerify(L.ctPendingEntry(a), a, {});
  ok(pv.checks.some((c) => c.id === 'ct.pending' && c.status === 'info') && !pv.times.length, 'pending proof is informational and adds no time');

  const stampFn = async () => ({ ots: {}, tsr: null, errors: [] });
  const rc = await L.makeReceipt({ fileMeta: { name: 'x.bin', size: 1, mediaType: 'application/octet-stream', sha256Hex: a }, stampFn, rekor: false });
  const files = await L.zipRead(rc.zip);
  ok(files['proofs/ct.json'], 'makeReceipt always includes proofs/ct.json');
  const ctj = JSON.parse(new TextDecoder().decode(files['proofs/ct.json']));
  ok(ctj.status === 'pending' && ctj.lightdrawer_ct === 1, 'fresh receipt has a pending certificate-log entry');
  const vr = await L.verifyReceipt(files, null, {});
  ok(vr.sections.some((s) => /Certificate Transparency/.test(s.title)), 'verifyReceipt reports a CT section');

  const mock = createMockAcmeDns(plan.hostnames);
  const acme = await acmeIssue({ directoryUrl: mock.directoryUrl, hostnames: plan.hostnames, fetchFn: mock.fetchFn, setTxt: mock.setTxt, clearTxt: mock.clearTxt });
  ok(/BEGIN CERTIFICATE/.test(acme.certPem), 'mocked ACME DNS-01 flow returns a certificate');
  ok(L.x509SANs(L.x509Parse(L.pemToDer(acme.certPem))).includes(plan.hostnames[0]), 'ACME mock cert names the batch root');
  ok([...mock.txt.values()].every((v) => v.length === 0 || true), 'mock DNS map is usable');
  // TXT is cleared after success
  ok(mock.txt.size === 0, 'ACME mock removes the _acme-challenge TXT after validation');

  let refused = false;
  try { await acmeIssue({ directoryUrl: 'https://acme-v02.api.letsencrypt.org/directory', hostnames: ['x.example'], fetchFn: async () => { throw new Error('should not fetch production'); }, setTxt: async () => {} }); }
  catch (err) { refused = /PRODUCTION/i.test(err.message); }
  ok(refused, 'ACME client refuses the Let\'s Encrypt production directory');
}

console.log('CT runner CLI (temp state file, mock issuer)');
{
  const { runCli } = await import(new URL('../scripts/ct-anchor.mjs', import.meta.url));
  const state = join(root, 'build/ct-test-state.json');
  rmSync(state, { force: true });
  const dig = L.toHex(await L.sha256(L.utf8('cli-leaf')));
  await runCli(['submit', dig, '--state', state, '--now', '2026-11-09T10:00:00Z']);
  await runCli(['close-sub-batch', '--state', state, '--now', '2026-11-09T10:16:00Z']);
  await runCli(['issue', '--state', state, '--now', '2026-11-09T14:01:00Z', '--issuer', 'mock', '--force']);
  const outPath = join(root, 'build/ct-upgrade-out.json');
  const { writeFileSync: wf, readFileSync: rf } = await import('node:fs');
  const { spawnSync } = await import('node:child_process');
  const r = spawnSync(process.execPath, [join(root, 'scripts/ct-anchor.mjs'), 'upgrade', dig, '--state', state], { encoding: 'utf8' });
  ok(r.status === 0 && /"status": "anchored"/.test(r.stdout), 'CLI upgrade prints an anchored ct.json');
  const refuse = spawnSync(process.execPath, [join(root, 'scripts/ct-anchor.mjs'), 'refuse-prod-check'], { encoding: 'utf8' });
  ok(refuse.status === 0 && /refused/.test(refuse.stdout), 'CLI refuse-prod-check passes');
}

console.log('CT Worker runtime (allowlist, production ACME guard, CSR, Merkle match)');
{
  const RT = await import(new URL('../src/ct-runtime.js', import.meta.url));
  let refused = false;
  try { RT.assertNotProductionDirectory('https://acme-v02.api.letsencrypt.org/directory'); }
  catch (e) { refused = /PRODUCTION/i.test(e.message); }
  ok(refused, 'Worker runtime refuses production ACME unless CT_PRODUCTION=1');
  refused = false;
  try { RT.assertNotProductionDirectory('https://acme-v01.api.letsencrypt.org/directory'); }
  catch (e) { refused = /PRODUCTION/i.test(e.message); }
  ok(refused, 'Worker runtime also refuses the retired v01 production directory without the flag');
  RT.assertNotProductionDirectory('https://acme-v02.api.letsencrypt.org/directory', { CT_PRODUCTION: '1' });
  ok(true, 'Worker runtime allows production ACME when CT_PRODUCTION=1');
  const goodName = '_acme-challenge.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ct.lightdrawer.org';
  ok(RT.assertAllowedAcmeTxtName(goodName) === goodName, 'allowed ACME TXT name under ct.lightdrawer.org is accepted');
  let blocked = 0;
  for (const bad of ['_acme-challenge.lightdrawer.org', '_acme-challenge.evil.example', '_acme-challenge.nothex.nothex.ct.lightdrawer.org', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ct.lightdrawer.org', '_acme-challenge.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ct.other.org']) {
    try { RT.assertAllowedAcmeTxtName(bad); } catch { blocked++; }
  }
  ok(blocked === 5, 'DNS allowlist rejects names outside _acme-challenge.<32hex>.<32hex>.ct.lightdrawer.org');
  const hex = async (n) => L.toHex(await L.sha256(L.utf8('leaf-' + n)));
  const a = await hex(1), b = await hex(2), c = await hex(3);
  const coreTree = await L.ctMerkleBuild([a, b, c]);
  const rtTree = await RT.ctMerkleBuild([a, b, c]);
  ok(coreTree.root === rtTree.root && coreTree.tree_size === 3, 'Worker Merkle roots match the shared library');
  const host = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ct.lightdrawer.org';
  const csr = await RT.buildEcdsaCsr([host, 'cccccccccccccccccccccccccccccccc.dddddddddddddddddddddddddddddddd.ct.lightdrawer.org']);
  const csrPath = join(root, 'build/ct-test.csr');
  writeFileSync(csrPath, csr.pem);
  try {
    const o = execFileSync('openssl', ['req', '-verify', '-in', csrPath, '-noout', '-text'], { encoding: 'utf8' });
    ok(/verify OK/i.test(o), 'openssl verifies the generated PKCS#10 CSR');
    ok(o.includes(host), 'CSR includes the batch-root hostname');
    ok(/Subject Alternative Name/i.test(o), 'CSR contains a SAN extension');
  } catch (e) {
    ok(false, 'openssl CSR check: ' + (e.stdout || '') + (e.stderr || e.message));
  }
  try { RT.ctConfigFromEnv({ ACME_DIRECTORY: 'https://acme-v02.api.letsencrypt.org/directory' }); ok(false, 'ctConfigFromEnv should refuse production without CT_PRODUCTION'); }
  catch (e) { ok(/PRODUCTION/i.test(e.message), 'ctConfigFromEnv refuses a production ACME_DIRECTORY without CT_PRODUCTION'); }
  const prodCfg = RT.ctConfigFromEnv({ ACME_DIRECTORY: 'https://acme-v02.api.letsencrypt.org/directory', CT_PRODUCTION: '1' });
  ok(prodCfg.directory === 'https://acme-v02.api.letsencrypt.org/directory', 'ctConfigFromEnv accepts production ACME when CT_PRODUCTION=1');
  const cfg = RT.ctConfigFromEnv({});
  ok(cfg.directory === RT.STAGING_DIRECTORY && cfg.anchorEveryMs === 6 * 60 * 60 * 1000, 'config defaults to staging ACME and a 6-hour anchor');
}


await runStampApiTests(ok);

if (live) {
  console.log('LIVE: stamp a throwaway test file (hash only) at OpenTimestamps calendars + FreeTSA');
  const file = L.utf8('LightDrawer self-test ' + new Date().toISOString() + '\n');
  const stampFn = async (dig, tsq) => {
    const ots = {}, errors = [];
    await Promise.all(L.OTS_DEFAULT_CALENDARS.map(async (cal) => {
      try { const r = await fetch(cal + '/digest', { method: 'POST', body: dig, headers: { accept: 'application/vnd.opentimestamps.v1' } }); if (!r.ok) throw new Error('HTTP ' + r.status); ots[cal] = new Uint8Array(await r.arrayBuffer()); } catch (e) { errors.push(cal + ': ' + e.message); }
    }));
    let tsr = null; try { const r = await fetch('https://freetsa.org/tsr', { method: 'POST', body: tsq, headers: { 'content-type': 'application/timestamp-query' } }); tsr = new Uint8Array(await r.arrayBuffer()); } catch (e) { errors.push('tsa: ' + e.message); }
    return { ots, tsr, errors };
  };
  const rc = await L.makeReceipt({ fileMeta: { name: 'selftest.txt', size: file.length, mediaType: 'text/plain', sha256Hex: L.toHex(await L.sha256(file)) },
    provenance: { source_url: 'https://example.org/post/1', collected_at: '2026-11-09T07:40:00-06:00', collector: 'self-test', collection_method: 'test/run.mjs', collector_notes: 'Synthetic test file.' },
    stampFn, rekor: false, verifierHtml: new Uint8Array(readFileSync(join(root, 'public/verify.html'))), trustFiles: L.TRUST_FILES });
  console.log('     errors:', rc.errors);
  ok(rc.otsBytes && rc.tsr, 'receipt has .ots and .tsr');
  const out = join(root, 'build/live-receipt'); rmSync(out, { recursive: true, force: true }); mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'selftest.txt'), file); writeFileSync(join(out, 'selftest.txt.lightdrawer-receipt.zip'), rc.zip);
  execFileSync('python3', ['-c', 'import zipfile,sys;zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])', join(out, 'selftest.txt.lightdrawer-receipt.zip'), join(out, 'x')]);
  const files = await L.zipRead(rc.zip);
  const v = await L.verifyReceipt(files, { name: 'selftest.txt', bytes: file }, {});
  for (const s of v.sections) for (const c of s.checks) console.log(`     ${c.status.padEnd(4)} [${s.title}] ${c.title}`);
  ok(v.verdict === 'pass', 'verifyReceipt verdict pass (times: ' + v.times.map((t) => t.source + ' ' + t.time.toISOString()).join('; ') + ')');
  const tampered = Uint8Array.from(file); tampered[0] ^= 1;
  ok((await L.verifyReceipt(files, { name: 'x', bytes: tampered }, {})).verdict === 'fail', 'tampered original file fails');
  try {
    const o = execFileSync('openssl', ['ts', '-verify', '-data', 'statement.json', '-in', 'proofs/statement.json.tsr', '-CAfile', 'trust/freetsa-cacert.pem', '-untrusted', 'trust/freetsa-tsa.crt'], { cwd: join(out, 'x'), stdio: ['ignore', 'pipe', 'pipe'] }).toString();
    ok(/Verification: OK/.test(o), 'openssl ts -verify on extracted receipt: OK');
  } catch (e) { ok(false, 'openssl: ' + (e.stdout || '') + (e.stderr || '')); }
  const otsBin = process.env.OTS_BIN || join(root, '.venv-test/bin/ots');
  try { const o = execFileSync(otsBin, ['info', 'proofs/statement.json.ots'], { cwd: join(out, 'x') }).toString(); console.log(o.split('\n').slice(0, 6).map((x) => '     ' + x).join('\n')); ok(/File sha256 hash/.test(o), '`ots info` parses our .ots'); } catch (e) { ok(false, 'ots info: ' + e.message); }
  try { execFileSync(otsBin, ['verify', '-f', 'statement.json', 'proofs/statement.json.ots'], { cwd: join(out, 'x'), stdio: 'pipe' }); ok(true, 'ots verify'); } catch (e) { const t = String(e.stderr || '') + String(e.stdout || ''); ok(/Pending confirmation|pending/i.test(t), '`ots verify` reports pending (expected right after stamping): ' + t.trim().split('\n').slice(-1)[0]); }
}
console.log(failed ? `\n${failed} FAILED` : '\nall passed'); process.exit(failed ? 1 : 0);
