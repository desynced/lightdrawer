#!/usr/bin/env node
// Mint or revoke trusted-caller stamp keys. Prints the plaintext key once
// (stdout); only the SHA-256 hash is meant to be stored in D1. Never commit
// a real key, hash insert of a production key, or command output that includes
// the plaintext.
import { generateStampKeyRecord, hashStampKey, insertStampKeySql, revokeStampKeySql } from '../src/stamp-keys.js';

const usage = `Usage:
  node scripts/stamp-key.mjs mint <label>
      Generate a key. Prints the plaintext once, then the hash-only SQL
      to insert it into D1. Label: start with a letter or digit, then
      letters, digits, ".", "_" or "-" (max 64 chars). Example: fairview

  node scripts/stamp-key.mjs hash
      Read a plaintext key from stdin and print its SHA-256 hex (for an
      insert you already have a key for). Does not write anything.

  node scripts/stamp-key.mjs revoke-sql <id>
      Print SQL that revokes the key with that UUID.

After mint, apply the table (once) and insert the hash:

  wrangler d1 execute lightdrawer-ct --remote --file=migrations/0001_stamp_keys.sql
  wrangler d1 execute lightdrawer-ct --remote --command "<the INSERT printed above>"

  # If you keep production IDs in a private file:
  #   wrangler d1 execute lightdrawer-ct --remote --file=migrations/0001_stamp_keys.sql -c wrangler.production.jsonc

List keys (labels only; hashes are not needed day to day):

  wrangler d1 execute lightdrawer-ct --remote --command "SELECT id, label, created_at, revoked_at FROM stamp_keys ORDER BY created_at"
`;

const [, , cmd, arg] = process.argv;
if (!cmd || cmd === '-h' || cmd === '--help') {
  process.stdout.write(usage);
  process.exit(cmd ? 0 : 2);
}

try {
  if (cmd === 'mint') {
    if (!arg) throw new Error('mint requires a label, e.g. node scripts/stamp-key.mjs mint fairview');
    const rec = await generateStampKeyRecord(arg);
    const sql = insertStampKeySql(rec);
    process.stdout.write(
      `Plaintext key (shown once — store it as a secret on the caller, e.g. Fairview LIGHTDRAWER_STAMP_KEY).\n` +
      `Do not commit this value.\n\n` +
      `  ${rec.token}\n\n` +
      `id:         ${rec.id}\n` +
      `label:      ${rec.label}\n` +
      `key_hash:   ${rec.key_hash}\n` +
      `created_at: ${rec.created_at}\n\n` +
      `Insert (hash only; safe to paste into wrangler d1 execute):\n\n` +
      `  wrangler d1 execute lightdrawer-ct --remote --command "${sql.replace(/"/g, '\\"')}"\n`
    );
  } else if (cmd === 'hash') {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    const token = Buffer.concat(chunks).toString('utf8').trim();
    if (!token) throw new Error('provide the plaintext key on stdin');
    process.stdout.write(await hashStampKey(token) + '\n');
  } else if (cmd === 'revoke-sql') {
    if (!arg) throw new Error('revoke-sql requires the key id (UUID)');
    const sql = revokeStampKeySql(arg);
    process.stdout.write(
      `  wrangler d1 execute lightdrawer-ct --remote --command "${sql.replace(/"/g, '\\"')}"\n`
    );
  } else {
    throw new Error('unknown command: ' + cmd);
  }
} catch (e) {
  process.stderr.write(String(e.message || e) + '\n');
  process.exit(1);
}
