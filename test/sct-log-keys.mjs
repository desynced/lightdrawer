import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

export async function runSctLogKeysTests(ok, L) {
  console.log('CT SCT log keys (real Let\'s Encrypt precertificate SCTs from the 4:01 PM CST 10 Nov 2026 certificate)');
  const entry = JSON.parse(readFileSync(join(root, 'test/fixtures/ct-2026-11-10-scts.json'), 'utf8'));
  const v = await L.ctVerify(entry, entry.digest, L.TRUST);
  for (const c of v.checks.filter((c) => c.id.startsWith('ct.sct') || c.id === 'ct.chain' || c.id === 'ct.merkle')) {
    console.log(`     ${c.status.padEnd(4)} ${c.title}${c.detail ? ' — ' + c.detail.slice(0, 120) : ''}`);
  }
  const sctChecks = v.checks.filter((c) => c.id.startsWith('ct.sct.'));
  ok(sctChecks.length === 2, 'parsed two embedded SCTs');
  ok(sctChecks.every((c) => c.status === 'pass'), 'both SCT signatures verify (no yellow warning)');
  ok(sctChecks.some((c) => /Argon2027h1/.test(c.title)), 'names Google Argon2027h1');
  ok(sctChecks.some((c) => /Gouda2027h1/.test(c.title)), 'names IPng Networks Gouda2027h1');
  ok(v.checks.some((c) => c.id === 'ct.chain' && c.status === 'pass'), 'certificate still chains to a pinned CA root');
  ok(v.checks.some((c) => c.id === 'ct.merkle' && c.status === 'pass'), 'Merkle path still checks out');
  ok(!v.checks.some((c) => c.id.startsWith('ct.sct') && (c.status === 'warn' || c.status === 'fail')), 'no SCT warn or fail');

  const leaf = L.x509Parse(L.pemToDer(entry.certificate_pem));
  const issuer = L.x509Parse(L.pemToDer(entry.chain_pems[0]));
  const scts = L.ctParseSctList(L.x509SctListBytes(leaf));
  ok(scts.length === 2, 'x509 SCT list parser sees two timestamps');
  const first = scts[0];
  const log = L.ctLookupLog(L.TRUST, first.logId);
  ok(!!log && /Argon2027h1/.test(log.name || ''), 'first SCT log id maps to the bundled Argon2027h1 key');
  const signed = await L.ctPrecertSignedData(first, leaf, issuer);
  ok(await L.ctVerifySctSignature(first, signed, log), 'raw precertificate signed-data verifies');
  const tampered = {
    version: first.version,
    logId: first.logId,
    timestampMs: first.timestampMs,
    extensions: first.extensions,
    hashAlg: first.hashAlg,
    sigAlg: first.sigAlg,
    signature: Uint8Array.from(first.signature),
  };
  tampered.signature[4] ^= 0x01;
  ok(!(await L.ctVerifySctSignature(tampered, signed, log)), 'tampered SCT signature is rejected');
  const x509Signed = L.ctSctSignedData(first, 0, leaf.der);
  ok(!(await L.ctVerifySctSignature(first, x509Signed, log)), 'the same SCT does not verify as an x509_entry over the final certificate');
}
