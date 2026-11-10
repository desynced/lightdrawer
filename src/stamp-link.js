// Parse and check "Stamp this with LightDrawer" links.
// ?expect=<64-hex> is the SHA-256 of the original file (not statement.json).
// #digest=<64-hex> is the same file hash, passed in the fragment so it is
// never sent to a server. Neither value is a receipt fingerprint (/r/<hash>).
// This module never writes HTML; the UI must use textContent, not innerHTML.

export const HEX64_RE = /^[0-9a-f]{64}$/;

export function normalizeHexHash(raw) {
  if (raw == null) return null;
  const s = String(raw).trim().toLowerCase();
  return HEX64_RE.test(s) ? s : null;
}

function readSearchParams(search) {
  const s = String(search == null ? '' : search);
  return new URLSearchParams(s.startsWith('?') ? s.slice(1) : s);
}

function readHashParams(hash) {
  const s = String(hash == null ? '' : hash);
  return new URLSearchParams(s.startsWith('#') ? s.slice(1) : s);
}

export function parseExpectQuery(search) {
  const params = readSearchParams(search);
  const present = params.has('expect');
  if (!present) return { present: false, hash: null };
  return { present: true, hash: normalizeHexHash(params.get('expect')) };
}

export function parseDigestFragment(hash) {
  const params = readHashParams(hash);
  const present = params.has('digest');
  if (!present) return { present: false, hash: null };
  return { present: true, hash: normalizeHexHash(params.get('digest')) };
}

export function resolveStampLink({ search = '', hash = '' } = {}) {
  const expect = parseExpectQuery(search);
  const digest = parseDigestFragment(hash);
  const invalid = (expect.present && !expect.hash) || (digest.present && !digest.hash);
  let expected = null;
  let source = null;
  if (digest.hash) {
    expected = digest.hash;
    source = 'fragment';
  }
  if (expect.hash) {
    if (!expected) {
      expected = expect.hash;
      source = 'query';
    }
  }
  const conflict = !!(digest.hash && expect.hash && digest.hash !== expect.hash);
  return { expected, source, conflict, invalid, expect, digest };
}

export function compareFileHash(fileHash, expected) {
  const file = normalizeHexHash(fileHash);
  const exp = normalizeHexHash(expected);
  if (!exp) return 'none';
  if (!file) return 'waiting';
  return file === exp ? 'match' : 'mismatch';
}

export function stampLinkNotice(resolution, fileHash) {
  const notices = [];
  if (!resolution) {
    return { comparison: 'none', notices, canStamp: true };
  }
  if (resolution.invalid) {
    notices.push({
      kind: 'invalid',
      title: 'This link included something that is not a fingerprint.',
      body: 'That extra part was ignored. You can still drop a file here to make a receipt.',
    });
  }
  if (resolution.conflict) {
    notices.push({
      kind: 'conflict',
      title: 'This link lists two different fingerprints.',
      body: 'Please choose the file you meant to stamp, or open LightDrawer from the start.',
    });
  }
  const comparison = compareFileHash(fileHash, resolution.expected);
  if (comparison === 'waiting') {
    notices.push({
      kind: 'waiting',
      title: 'A website asked you to stamp a file with a known fingerprint.',
      body: 'Drop that same file here to confirm it. The file stays on this device and is never uploaded.',
      hash: resolution.expected,
    });
  }
  if (comparison === 'match') {
    notices.push({
      kind: 'match',
      title: 'This file matches the fingerprint the other site sent.',
      body: 'You can finish the check below to get your receipt.',
      hash: resolution.expected,
    });
  }
  if (comparison === 'mismatch') {
    notices.push({
      kind: 'mismatch',
      title: 'This file does not match the fingerprint the other site sent.',
      body: 'Please choose the same file you started with. If you meant to stamp this file instead, open LightDrawer without that extra link.',
      expected: resolution.expected,
      actual: normalizeHexHash(fileHash),
    });
  }
  return { comparison, notices, canStamp: comparison !== 'mismatch' };
}
