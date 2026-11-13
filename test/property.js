// Randomized checks for the parsers and the receipt helpers.
// Offline only: no calendars, no FreeTSA, no Rekor writes.
import fc from 'fast-check';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DIGEST_RE, normalizeDigest } from '../src/receipt-lookup.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const RUNS = 60;
const hexChar = fc.constantFrom(...'0123456789abcdef');
const hexString = (minLength, maxLength) => fc.string({ unit: hexChar, minLength, maxLength });

function loadCore() {
  const core = readFileSync(join(root, 'build/core.js'), 'utf8');
  const names = ['toHex', 'fromHex', 'utf8', 'utf8dec', 'sha256', 'bytesEq', 'tsaBuildRequest', 'otsParseDetached', 'otsSerializeDetached', 'zipWrite', 'zipRead', 'buildStatement', 'makeReceipt', 'verifyReceipt', 'ctMerkleBuild', 'ctMerkleVerify'];
  return new Function(core + `\nreturn { ${names.join(', ')} };`)();
}

function containsBytes(haystack, needle) {
  if (needle.length === 0) return true;
  for (let i = 0; i <= haystack.length - needle.length; i++) {
    let match = true;
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) { match = false; break; }
    if (match) return true;
  }
  return false;
}

function flipHexChar(hex) {
  const alphabet = '0123456789abcdef';
  const at = alphabet.indexOf(hex[0]);
  return alphabet[(at + 1) % 16] + hex.slice(1);
}

function isBadHexError(e) {
  return e instanceof Error && e.message === 'bad hex';
}

async function holds(ok, label, run) {
  try {
    await run();
    ok(true, label);
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    ok(false, label + ': ' + msg.slice(0, 500));
  }
}

export async function runPropertyTests(ok) {
  const L = loadCore();
  console.log('Property tests (fast-check)');

  await holds(ok, 'hex round-trip, lowercase even length, whitespace still parses (' + RUNS + ' runs)', () => fc.assert(fc.asyncProperty(
    fc.uint8Array({ minLength: 0, maxLength: 48 }),
    async (bytes) => {
      const hex = L.toHex(bytes);
      if (!/^[0-9a-f]*$/.test(hex) || hex.length !== bytes.length * 2) return false;
      if (!L.bytesEq(L.fromHex(hex), bytes)) return false;
      if (!L.bytesEq(L.fromHex(hex.toUpperCase()), bytes)) return false;
      if (!L.bytesEq(L.fromHex(' \t' + hex + '\n'), bytes)) return false;
      return true;
    },
  ), { numRuns: RUNS }));

  // Whitespace-only input trims to "" (even length, no non-hex character), so it
  // is accepted as zero bytes. Odd lengths and non-hex characters throw "bad hex".
  const blank = L.fromHex(' \t\n');
  ok(blank.length === 0, 'whitespace-only hex trims to empty and is accepted');

  await holds(ok, 'fromHex rejects odd length and non-hex with "bad hex" (' + RUNS + ' runs)', () => fc.assert(fc.property(
    hexString(1, 15).filter((s) => s.length % 2 === 1),
    fc.string({ unit: fc.constantFrom('g', 'z', 'G', '!', '/'), minLength: 1, maxLength: 4 }),
    fc.string({ unit: fc.constantFrom(' ', '\t', '\n'), maxLength: 2 }),
    (odd, junk, pad) => {
      let oddError = null;
      let junkError = null;
      try { L.fromHex(pad + odd + pad); } catch (e) { oddError = e; }
      try { L.fromHex(pad + junk + pad); } catch (e) { junkError = e; }
      return isBadHexError(oddError) && isBadHexError(junkError);
    },
  ), { numRuns: RUNS }));

  await holds(ok, 'statement bytes are canonical pretty JSON plus a newline (' + RUNS + ' runs)', () => fc.assert(fc.asyncProperty(
    fc.string({ maxLength: 40 }),
    fc.integer({ min: 0, max: 50000000 }),
    fc.string({ maxLength: 40 }),
    hexString(64, 64),
    fc.record({
      source_url: fc.string({ maxLength: 40 }),
      source_archive_url: fc.string({ maxLength: 40 }),
      collected_at: fc.string({ maxLength: 40 }),
      collector: fc.string({ maxLength: 40 }),
      collection_method: fc.string({ maxLength: 40 }),
      collector_notes: fc.string({ maxLength: 40 }),
    }),
    async (name, size, mediaType, sha256Hex, provenance) => {
      const built = await L.buildStatement({ name, size, mediaType, sha256Hex, provenance });
      const text = L.utf8dec(built.bytes);
      const canonical = JSON.stringify(built.statement, null, 2) + '\n';
      if (!L.bytesEq(built.bytes, L.utf8(canonical))) return false;
      if (!L.bytesEq(built.digest, await L.sha256(built.bytes))) return false;
      if (built.statement.subject.sha256 !== sha256Hex) return false;
      const again = JSON.stringify(JSON.parse(text), null, 2) + '\n';
      return again === text;
    },
  ), { numRuns: RUNS }));

  const otsFixture = new Uint8Array(readFileSync(join(root, 'test/fixtures/hello-world.txt.ots')));
  const otsParsed = await L.otsParseDetached(otsFixture);
  ok(L.bytesEq(L.otsSerializeDetached(otsParsed.digest, otsParsed.root), otsFixture), 'hello-world.ots parse → serialize is byte-exact');

  await holds(ok, 'mutated .ots bytes throw an Error or return a structure (' + RUNS + ' runs)', () => fc.assert(fc.asyncProperty(
    fc.integer({ min: 0, max: Math.max(0, otsFixture.length - 1) }),
    fc.integer({ min: 0, max: 255 }),
    fc.constantFrom('flip', 'truncate', 'insert'),
    async (index, byte, kind) => {
      let mutated;
      if (kind === 'flip') {
        mutated = Uint8Array.from(otsFixture);
        mutated[index] ^= (byte % 255) + 1;
      } else if (kind === 'truncate') {
        mutated = otsFixture.subarray(0, index);
      } else {
        mutated = new Uint8Array(otsFixture.length + 1);
        mutated.set(otsFixture.subarray(0, index), 0);
        mutated[index] = byte;
        mutated.set(otsFixture.subarray(index), index + 1);
      }
      try {
        const parsed = await L.otsParseDetached(mutated);
        return !!(parsed && parsed.digest && parsed.root);
      } catch (e) {
        return e instanceof Error;
      }
    },
  ), { numRuns: RUNS }));

  await holds(ok, 'zip write/read keeps safe names and bytes (' + RUNS + ' runs)', () => fc.assert(fc.asyncProperty(
    fc.array(fc.uint8Array({ minLength: 0, maxLength: 40 }), { minLength: 0, maxLength: 4 }),
    fc.array(hexString(1, 8), { minLength: 0, maxLength: 4 }),
    async (datas, nameParts) => {
      const files = datas.map((data, i) => ({ name: 'f' + i + '-' + (nameParts[i] || 'x') + '.bin', data }));
      const read = await L.zipRead(L.zipWrite(files));
      if (Object.keys(read).length !== files.length) return false;
      for (const file of files) {
        if (!L.bytesEq(read[file.name], file.data)) return false;
      }
      return true;
    },
  ), { numRuns: RUNS }));

  await holds(ok, 'a broken statement.json fails closed, and a different file hash does not pass (' + RUNS + ' runs)', () => fc.assert(fc.asyncProperty(
    fc.uint8Array({ minLength: 1, maxLength: 32 }),
    hexString(4, 8),
    fc.constantFrom('missing', 'not-json', 'truncated'),
    async (bytes, namePart, kind) => {
      const sha256Hex = L.toHex(await L.sha256(bytes));
      const built = await L.makeReceipt({
        fileMeta: { name: 'f-' + namePart + '.bin', size: bytes.length, mediaType: 'application/octet-stream', sha256Hex },
        stampFn: async () => ({ ots: {}, tsr: null, errors: [] }),
        rekor: false,
      });
      const files = await L.zipRead(built.zip);
      const good = await L.verifyReceipt(files, { name: 'f-' + namePart + '.bin', bytes, size: bytes.length }, {});
      const goodHash = good.sections.flatMap((s) => s.checks).find((c) => c.id === 'file.hash');
      if (!goodHash || goodHash.status !== 'pass') return false;

      const flipped = Uint8Array.from(bytes);
      flipped[0] ^= 0xff;
      const wrong = await L.verifyReceipt(files, { name: 'other.bin', bytes: flipped, size: flipped.length }, {});
      const wrongHash = wrong.sections.flatMap((s) => s.checks).find((c) => c.id === 'file.hash');
      if (!wrongHash || wrongHash.status === 'pass' || wrong.verdict === 'pass') return false;

      const broken = Object.assign({}, files);
      if (kind === 'missing') delete broken['statement.json'];
      else if (kind === 'not-json') broken['statement.json'] = L.utf8('not json');
      else broken['statement.json'] = files['statement.json'].subarray(0, 8);
      try {
        const out = await L.verifyReceipt(broken, null, {});
        const checks = out.sections.flatMap((s) => s.checks);
        return checks.some((c) => c.status === 'fail') || out.verdict === 'fail';
      } catch {
        return false;
      }
    },
  ), { numRuns: RUNS }));

  await holds(ok, 'RFC 3161 requests are DER sequences with a fresh nonce (' + RUNS + ' runs)', () => fc.assert(fc.property(
    fc.uint8Array({ minLength: 32, maxLength: 32 }),
    (digest) => {
      const a = L.tsaBuildRequest(digest);
      const b = L.tsaBuildRequest(digest);
      return a.tsq[0] === 0x30 && b.tsq[0] === 0x30 && containsBytes(a.tsq, digest) && containsBytes(b.tsq, digest) && a.nonceHex !== b.nonceHex;
    },
  ), { numRuns: RUNS }));

  await holds(ok, 'Merkle build then verify, and a changed leaf or root fails (' + RUNS + ' runs)', () => fc.assert(fc.asyncProperty(
    fc.uniqueArray(hexString(64, 64), { minLength: 1, maxLength: 5 }),
    async (digests) => {
      const tree = await L.ctMerkleBuild(digests);
      for (const leaf of tree.leaves) {
        const proof = tree.proofs[leaf];
        if (!(await L.ctMerkleVerify(leaf, proof.index, proof.path, tree.root, tree.tree_size))) return false;
      }
      const leaf = tree.leaves[0];
      const proof = tree.proofs[leaf];
      let changed = flipHexChar(leaf);
      if (tree.leaves.includes(changed)) changed = flipHexChar(changed);
      const badLeaf = await L.ctMerkleVerify(changed, proof.index, proof.path, tree.root, tree.tree_size);
      const badRoot = await L.ctMerkleVerify(leaf, proof.index, proof.path, flipHexChar(tree.root), tree.tree_size);
      return badLeaf === false && badRoot === false;
    },
  ), { numRuns: RUNS }));

  const sample = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  ok(DIGEST_RE.test(sample) && normalizeDigest(sample) === sample, '64 lowercase hex is accepted');
  // normalizeDigest trims and lowercases before DIGEST_RE, so uppercase and mixed case pass.
  // DIGEST_RE itself stays lowercase-only, which is the same rule as "digest must be 64 hex chars".
  ok(normalizeDigest(sample.toUpperCase()) === sample, 'uppercase hex is lowercased, then accepted');
  ok(!DIGEST_RE.test(sample.toUpperCase()), 'DIGEST_RE itself rejects uppercase');
  ok(normalizeDigest('') === null, 'empty digest is rejected');

  await holds(ok, 'lookup digest rejects the wrong length and any non-hex character (' + RUNS + ' runs)', () => fc.assert(fc.property(
    hexString(64, 64),
    fc.string({ maxLength: 80 }).filter((s) => !/^[0-9a-fA-F]{64}$/.test(s.trim())),
    (hex, bad) => {
      const mixed = hex.split('').map((c, i) => (i % 2 ? c.toUpperCase() : c)).join('');
      return normalizeDigest(hex) === hex
        && normalizeDigest('  ' + mixed + '\n') === hex
        && normalizeDigest(bad) === null;
    },
  ), { numRuns: RUNS }));
}
