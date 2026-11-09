# LightDrawer

![LightDrawer](examples/brand/logo-lockup.png)

**Prove this file existed, unchanged, at this time — and let anyone check it without trusting us.**

Drop a file. Get a receipt. Anyone can check it later — even if this website is gone.

Your file never leaves your device. LightDrawer only uses a *fingerprint*, a short unique code of that exact file, and independent witnesses record that it existed at that moment: Bitcoin, a timestamp authority, and public certificate logs.

It is for journalists, photographers, artists, small businesses, and anyone who needs to show that a photo, video, or document has not been changed since they saved it — for example, when documenting damage for insurance.

![How LightDrawer works](examples/how-it-works.png)

![Demo: make a receipt and check it](examples/lightdrawer-demo.gif)

## How it works

1. **Drop your file** on the site. It is fingerprinted on your device, so the file itself is never uploaded.
2. **Get your receipt** — a small download to keep with the original file, like a time-stamped ticket.
3. **Anyone can check it** by opening the receipt and, if they have it, the original file. They do not need an account, and they do not have to trust us. Every receipt includes its own checker.

Optional notes about where a file came from can be included. They are saved with the receipt, but they remain your own statements.

A longer, precise walkthrough — what leaves your device, how each proof is built, what is stored, and how to check a receipt with ordinary tools — is in [HOW-IT-WORKS.md](HOW-IT-WORKS.md).

## What's in the receipt

```
<file>.lightdrawer-receipt.zip
├── README.html / README.txt     cover page: what is proven, when, how to check by hand, limits
├── statement.json               the exact bytes that were timestamped (file SHA-256 + optional notes)
├── receipt.json                 machine-readable index (calendars, TSA nonce, Rekor uuid, errors)
├── proofs/statement.json.ots    OpenTimestamps Bitcoin proof (merged from 3 public calendars)
├── proofs/statement.json.tsr    FreeTSA RFC 3161 token
├── proofs/ct.json               certificate-log proof (pending until the next batch certificate)
├── proofs/rekor-entry.json      optional Sigstore Rekor entry (off by default; public and permanent)
├── trust/                       convenience copies of FreeTSA certs and the Rekor public key
└── verify.html                  single-file offline verifier
```

Why a statement instead of the bare file hash: optional notes need to be covered by the same timestamps. Chain: `file → sha256 → statement.json → sha256 → proofs`. Both steps are checkable with `sha256sum`.

## What it proves / what it does not

| Proves | Does not prove |
|---|---|
| A file with this exact SHA-256, plus the statement, existed **no later than** the stamped times | Who made the file or who stamped it |
| The notes were written no later than those times | That the file is authentic, unedited before stamping, or true |
| | That the notes are accurate |
| | Anything about the file without the original bytes (keep the original) |

Timing: FreeTSA (RFC 3161) is immediate. OpenTimestamps is **pending for about 1–6 hours** until a Bitcoin block includes it; after upgrade, no trusted party is required. The certificate-log stamp is pending until the next batch certificate (sub-batches close about every 15 minutes; a certificate is requested about every 6 hours). Rekor (if enabled) is immediate and public.

## Privacy

Only the fingerprint (SHA-256) leaves the device. The file is never uploaded or stored. Files are fingerprinted in 4 MB chunks, so a large video is never loaded fully into memory. The Worker persists SHA-256 fingerprints (not files) in a D1 database (`CT_DB` / `lightdrawer-ct`) until they are sealed into a batch, plus the resulting Merkle data and issued certificate PEMs so a receipt can be upgraded later; see [HOW-IT-WORKS.md](HOW-IT-WORKS.md). Rekor is off by default because a Rekor entry is a public, permanent log of that hash.

For a public source, archive it yourself (perma.cc, Wayback Machine, Arweave) and paste that link into the notes fields.

## Built on (honest credits)

LightDrawer does not invent hashing or timestamps. It packages existing standards into one easy receipt:

- **[OpenTimestamps](https://opentimestamps.org)** — Bitcoin calendar timestamps (the free core of “hash + stamp + verify”)
- **[FreeTSA](https://freetsa.org)** — RFC 3161 timestamp authority
- **Certificate Transparency logs** — extra witness: batch fingerprints into a Merkle tree, encode each root as a hostname, and let a public HTTPS certificate (Let's Encrypt) appear in CT logs. Not a replacement for Bitcoin.
- **[Sigstore Rekor](https://docs.sigstore.dev)** — optional public transparency log (off by default)
- **C2PA Content Credentials** — *read* only; not validated
- **Berkeley Protocol–style fields** — optional provenance notes inside the stamped statement (collector’s own claims)

Paid services (Bernstein, OriginStamp, and others) and app-bound tools (e.g. ProofMode for photos) cover related ground. This project’s bet is a free, readable, self-contained receipt plus an offline verifier that still works if the site disappears.

## Quick start

Needs Node 20+ for build/tests. Current Wrangler wants Node 22+ (use `npx -p node@22` if your default is older).

```sh
npm install
npm test               # build + crypto/self tests (read-only Bitcoin block lookup for a fixture)
npm run test:live      # also stamps a throwaway hash at OTS + FreeTSA; needs openssl and `ots`
npm run dev            # wrangler dev → http://127.0.0.1:8787 (local only)
# Wrangler on Node 22 if needed:
npx -p node@22 npm run dev
python3 test/e2e_browser.py   # Playwright: make a receipt in the UI, verify from file://
npm run check          # wrangler deploy --dry-run (validates config, uploads nothing)
```

`test:live` expects the `ots` client at `.venv-test/bin/ots` (or `OTS_BIN`).

Code layout: `web/lib/*.js` are plain scripts (no bundler), concatenated by `scripts/build.mjs` into `public/app.js` and inlined into single-file `public/verify.html`. Trust anchors in `trust/` are pinned into the build. `src/worker.js` is the only server code.

## Self-host on Cloudflare

Workers + Static Assets (`wrangler.jsonc`). A D1 database (`lightdrawer-ct`, bound as `CT_DB`) holds the certificate-log queue. A cron trigger runs every 15 minutes to close sub-batches and to advance two-phase ACME issuance. No Durable Objects, Workflows, R2, or KV are bound — the original file never leaves the browser. `scripts/ct-anchor.mjs` remains the offline/mock prototype of the same math.

The committed `wrangler.jsonc` is a template with placeholders (empty Turnstile site key, `<your-d1-database-id>`). Keep real deploy IDs out of git: copy it to a private `wrangler.production.jsonc` (gitignored in this repo) and deploy with `wrangler deploy -c wrangler.production.jsonc`.

1. Create a Turnstile widget for your domain. Put the **site key** in a Worker secret (preferred) or only in your private deploy config — do not commit a real value:
   `printf '%s' '<site-key>' | wrangler secret put TURNSTILE_SITE_KEY`
   Also `wrangler secret put TURNSTILE_SECRET` (recommended for a public site). The browser loads the site key from `GET /api/config` at runtime, so static files never hard-code it. Until `TURNSTILE_SECRET` is set, `/api/stamp` skips the human check so local development still works.
2. For the certificate-log stamp, set a Cloudflare API token scoped **only** to Zone DNS Edit on your domain as the Worker secret `CF_DNS_TOKEN`. Also set the zone's ID as the secret `CF_ZONE_ID` (`wrangler secret put CF_ZONE_ID`), and replace the D1 `database_id` placeholder in your deploy config with your own (`wrangler d1 create lightdrawer-ct`). `scripts/ct-issue-remote.mjs` reads `CLOUDFLARE_ACCOUNT_ID`, `CT_DB_ID`, `CF_ZONE_ID`, and `CF_DNS_TOKEN` from the environment. The Worker will create and then delete `_acme-challenge` TXT records under your `CT_HOSTNAME_SUFFIX` only (hosted site uses `ct.lightdrawer.org`).
3. Keep `ACME_DIRECTORY` on the Let's Encrypt staging URL until you have rehearsed issuance. Production ACME directories are refused unless you also set `CT_PRODUCTION` to `"1"`. The hosted site at lightdrawer.org sets both; self-hosters can stay on staging.
4. Add a custom-domain route in your deploy config when you want the Worker on your own domain. Omit it to stay on workers.dev (the hosted project also keeps `workers_dev` enabled).
5. Set `DEFAULT_UPGRADE_PROXY` in `web/ui/verify-ui.js` (and the matching input value in `web/ui/verify.html`) to your public URL. The hosted site uses `https://lightdrawer.org`; self-hosters can use their own `*.workers.dev` URL.
6. Add a WAF rate-limiting rule on `/api/*` (e.g. 20 req / 10 s per IP for `/api/stamp`) before going public, if your Cloudflare plan allows it. Be a good neighbour to free calendars and FreeTSA.
7. `wrangler deploy` (or `wrangler deploy -c wrangler.production.jsonc` if you keep production IDs in that private file).

### What runs where

| Piece | Where it runs | Notes |
|---|---|---|
| Site (`index.html`, `app.js`, `verify.html`) | **Cloudflare Workers Static Assets** | Static; `_headers` sets CSP and other security headers |
| Hashing, statement, ZIP, receipt assembly, local proof checks | **User's browser** (WebCrypto) | File bytes never leave the device |
| `POST /api/stamp` | **Cloudflare Worker** (`src/worker.js`) | Forwards the 32-byte hash to OTS calendars and the RFC 3161 query to FreeTSA (they send no CORS). Browser posts are same-origin only, with Turnstile when the secret is set. Trusted server callers may send `Authorization: Bearer <key>` instead (see below). 10 req/min per IP, or per API key; Bearer attempts are also limited per IP (20/min) before the key is looked up |
| `GET /api/ots/upgrade` | **Cloudflare Worker** | CORS `*` so `verify.html` works from `file://`; calendar host allowlist; edge-cached 1 h; 60 req/min/IP |
| `GET /api/ct/upgrade` | **Cloudflare Worker** | CORS `*`; returns pending until the digest's batch has a stored certificate |
| Cron `*/15 * * * *` and `POST /api/ct/tick` | **Cloudflare Worker** | Closes due sub-batches; two-phase ACME issuance when `CF_DNS_TOKEN` is set (staging by default; production only if `CT_PRODUCTION=1`) |
| OpenTimestamps calendars / Bitcoin / FreeTSA / Rekor / CT logs | **External** | LightDrawer runs no calendar and does no own anchoring. Rekor is called **directly from the browser** (CORS OK). Certificate-log stamps use Let's Encrypt + public CT logs |

## Server-to-server stamps (API keys)

The public site asks a browser to pass a human check (Cloudflare Turnstile) before it will stamp a hash. Another server — for example a Worker that wants to stamp its own session digests — cannot complete that check. For those trusted callers you can mint a per-caller API key.

Only the SHA-256 hash of the key is stored, in the existing D1 database (`stamp_keys`). The plaintext key is shown once when you mint it and should live as a secret on the caller, not in this repo. A request that sends a valid key in `Authorization: Bearer …` skips Turnstile and uses its own 10-stamps-per-minute limit. Any request that presents a Bearer header is first limited to about 20 attempts per IP per minute, before LightDrawer looks the key up in D1, so junk keys cannot flood the database. Worker logs record the key's label (for example `fairview`); the public receipt is unchanged and does not name the caller. Requests without a key behave exactly as they do today.

Create the table on an existing database (once), then mint a key and insert only its hash:

```sh
wrangler d1 execute lightdrawer-ct --remote --file=migrations/0001_stamp_keys.sql
# If you deploy with a private config: add -c wrangler.production.jsonc to these commands.

node scripts/stamp-key.mjs mint fairview
# Copy the plaintext key into the caller's secret store (shown once).
# Then run the printed wrangler d1 execute … --command "INSERT …" line
# (that SQL contains the hash, not the key).
```

List and revoke:

```sh
wrangler d1 execute lightdrawer-ct --remote --command "SELECT id, label, created_at, revoked_at FROM stamp_keys ORDER BY created_at"
node scripts/stamp-key.mjs revoke-sql <id>
# Then run the printed UPDATE command.
```

Example request (the body is the same as a browser stamp — a 64-character SHA-256 hex digest, and optionally a FreeTSA `tsq`):

```sh
curl -sS https://lightdrawer.org/api/stamp \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $LIGHTDRAWER_STAMP_KEY" \
  --data '{"digest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'
```

The JSON response is still `{ "ots": { … }, "tsr": null, "errors": [] }` (`tsr` is `null` when the caller omits `tsq`). An empty, unknown, or revoked Bearer key is rejected with HTTP 401 `{"error":"Invalid or revoked API key."}`. Hitting the per-key limit, or the per-IP Bearer-attempt limit, returns HTTP 429 `{"error":"Too many requests. Try again in a minute."}`. A browser request with no `Authorization` header still needs a Turnstile token when `TURNSTILE_SECRET` is set. `/api/stamp` still sends no CORS headers, so this path is for a server caller (no `Origin` header required), not for JavaScript running in another site's page.

New installs that apply `schema/ct.sql` already include the `stamp_keys` table. Self-hosters who use Wrangler migrations can run `wrangler d1 migrations apply lightdrawer-ct --remote` instead of the `--file` command above.

## Verify without LightDrawer

```sh
sha256sum original.jpg            # must equal statement.json "subject.sha256"
sha256sum statement.json          # every proof is about this hash
openssl ts -verify -data statement.json -in proofs/statement.json.tsr \
  -CAfile freetsa-cacert.pem -untrusted freetsa-tsa.crt   # certs from https://freetsa.org/files/
pip install opentimestamps-client
ots upgrade proofs/statement.json.ots && ots verify -f statement.json proofs/statement.json.ots
curl https://rekor.sigstore.dev/api/v1/log/entries/<uuid>  # if a Rekor entry exists
```

Or open `verify.html` (works from `file://`; sends nothing unless you opt in to online checks).

## Limits / known gaps

- **OTS pending ~1–6 h.** Fresh receipts need an upgrade later (`verify.html` via the proxy, or `ots upgrade`). Keep the upgraded `.ots`.
- **C2PA** is read, not validated (no COSE / hash-binding / trust-list checks). JPEG, PNG, and a generic JUMBF scan are supported. To avoid loading multi-GB files, only the first 16 MB are scanned for Content Credentials.
- **FreeTSA revocation** (CRL/OCSP) is not checked offline. Only FreeTSA's pinned root is trusted (SHA-256 `a6379e7c…18aabc`).
- **Certificate-log stamp** is an extra witness, not a Bitcoin replacement. Let's Encrypt allows 50 new certificates per registered domain per 7 days (refill: 1 every 202 minutes; [rate-limits docs](https://letsencrypt.org/docs/rate-limits/), updated 5 August 2026) and 100 names per certificate. Default schedule: 15-minute sub-batches, a certificate about every 6 hours (~28/week, leaving room for retries). Failed issuance does not immediately retry; the Worker waits the same interval before starting another order. CT logs advertise a maximum merge delay of about 24 hours; they are sharded by certificate expiry and retired shards may stop answering queries (crt.sh and other archives keep copies). The Worker allows Let's Encrypt production only when `CT_PRODUCTION=1` (the hosted lightdrawer.org site sets this). Staging remains the code default. `scripts/ct-anchor.mjs` still refuses production directories. Self-hosters can stay on workers.dev and staging.
- **Rekor submission was not exercised live** (permanent public write). Verification against a real public entry is tested. Uses Rekor v1 at rekor.sigstore.dev; Sigstore is moving toward v2 — recheck before relying on it.
- **OpenTimestamps ops:** sha256, sha1, ripemd160, append, prepend, reverse, hexlify. No keccak256. Bitcoin attestations checked against two public explorers when online checks are on, not a local node.

## Optional later

- **R2 bucket locks** only if you ever host *receipts* (not files) for people. Not a substitute for Bitcoin anchoring.
- **Self-hosters:** leave `CT_PRODUCTION` unset and `ACME_DIRECTORY` on staging until you have rehearsed issuance on your own domain. Keep `CF_DNS_TOKEN` scoped to Zone DNS Edit on that domain only, and point `DEFAULT_UPGRADE_PROXY` at your own workers.dev or custom domain. See [HOW-IT-WORKS.md](HOW-IT-WORKS.md).

## Examples

- `examples/how-it-works.png` — one-page diagram of the flow.
- `examples/lightdrawer-demo.gif` — short walkthrough: pick a file → receipt → verify → tamper fails.
- `examples/demo/harbor-photo.jpg` — sample file used in the demo (plus an edited copy that fails verification).
- `examples/c2pa-sample-receipt/` — browser-made receipt for the C2PA test image (with provenance fields).
- `examples/selftest-receipt/` — receipt from `npm run test:live` plus its original file.
- `examples/*.png` — screenshots of the maker, verifier, and cover page.

## Support

LightDrawer is free and runs on donated time and free public witnesses. If it's useful to you, you can help keep it running at [paypal.me/josephball](https://paypal.me/josephball).

## License

MIT. See [`LICENSE`](LICENSE).
