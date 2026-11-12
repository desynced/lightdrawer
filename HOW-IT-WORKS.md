# How LightDrawer works

This page is the long version. The short version is still: **only a fingerprint leaves your device**, and the receipt lets anyone check that fingerprint later without trusting LightDrawer.

It describes what the code actually does today (`web/lib/`, `src/worker.js`, `src/ct-runtime.js`, `scripts/ct-anchor.mjs`). The hosted site at https://lightdrawer.org binds D1 and a 15-minute cron and talks to Let's Encrypt production because `CT_PRODUCTION=1`. The code default remains staging, so a self-hosted workers.dev deploy stays on staging until that flag is set. `scripts/ct-anchor.mjs` still refuses production directories.

## 1. What leaves the device

The file never does. The browser reads it in 4 MB chunks (`file.slice()` / a `Blob` stream) and computes SHA-256 incrementally with a small FIPS 180-4 implementation inlined into the page (WebCrypto's `digest()` is not incremental). A multi-gigabyte video is never loaded into memory all at once. Progress is shown while hashing. The result is byte-identical to `sha256sum`, WebCrypto, and Node's `crypto`. Then the browser builds a small `statement.json` that contains that fingerprint plus any optional notes you typed, and computes `SHA-256(statement.json)` (that one is small, so WebCrypto is fine). **That second hash is what every proof is about.** Content Credentials (C2PA) are read from only the first 16 MB of the file so the same large-video case does not pull the whole file into memory just to look for a manifest.

Chain:

```
file  ->  SHA-256  ->  statement.json  ->  SHA-256  ->  proofs
```

Both steps are checkable with `sha256sum`. Lose the original file and the receipt can no longer be tied to any content.

### What the browser sends to LightDrawer

`POST /api/stamp` (same-origin only). Example body:

```json
{
  "digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "tsq": "MHsCAQEwMTANBglghkgBZQMEAgEFAAQg47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFWgCQIBAf8EBQEB/wEBhAMhAP8=",
  "turnstile": "0.optional-token-only-when-Turnstile-is-configured"
}
```

- `digest` is 64 lowercase hex characters: the SHA-256 of `statement.json`, not of the original file name or path.
- `tsq` is the base64 encoding of an RFC 3161 `TimeStampReq` for that same digest (built in the browser). The Worker rejects a request whose decoded `tsq` is larger than 256 bytes, does not look like DER (`0x30...`), or does not contain those 32 digest bytes. It does this so it cannot be used as an open relay for arbitrary POSTs to FreeTSA.
- `turnstile` is sent only if a Turnstile site key is configured. If `TURNSTILE_SECRET` is set on the Worker, a missing or failed token is rejected with HTTP 403.
- A trusted server caller may send `Authorization: Bearer <key>` instead of a Turnstile token. The Worker hashes the key (SHA-256) and looks up that hash in D1 table `stamp_keys`. A match that has not been revoked skips the human check and uses a per-key 10/minute limit. Any Bearer header is first limited per IP (`stamp:auth:<ip>`, 20/minute) before that D1 lookup. The key's `label` is written to Worker logs only; it is not added to the JSON response or the receipt. Unknown, revoked, or empty Bearer values return HTTP 401 `{"error":"Invalid or revoked API key."}`. A keyed caller that hits the per-key limit, or any Bearer attempt that hits the per-IP auth limit, receives HTTP 429 `{"error":"Too many requests. Try again in a minute."}`. Requests with no `Authorization` header are unchanged.

Nothing else about the file — name, bytes, notes — is in this request. The notes live inside `statement.json`, which stays on your device and goes into the receipt ZIP.

The Worker then, for that 32-byte digest only:

1. `POST {calendar}/digest` to each of three OpenTimestamps calendars, with the **raw 32 bytes** as the body (`https://a.pool.opentimestamps.org`, `https://b.pool.opentimestamps.org`, `https://a.pool.eternitywall.com`).
2. If a `tsq` was provided, `POST https://freetsa.org/tsr` with the decoded `tsq` and `Content-Type: application/timestamp-query`. Callers may omit `tsq` (the response then has `"tsr": null`).
3. If a D1 binding named `CT_DB` is present (it is bound as `lightdrawer-ct` in `wrangler.jsonc`), `INSERT OR IGNORE` the hex digest and the current time into `ct_pending`. The same database may also hold `stamp_keys` (API key hashes and labels for trusted callers). File bytes are never stored.

The JSON response is `{ "ots": { "<calendar url>": "<base64>" }, "tsr": "<base64 or null>", "errors": [] }`. The browser merges those into the receipt ZIP on your device.

### Open MCP stamp lane

`POST /api/mcp/stamp` is a separate entrance used by the [LightDrawer MCP server](https://github.com/desynced/lightdrawer-mcp) (and any similar local tool). It exists so a developer’s AI client can stamp a hash without a browser human check and without sharing an API key.

Request body (same shape as a keyed `/api/stamp`, no `Authorization` header, no Turnstile token):

```json
{
  "digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "tsq": "MHsCAQEwMTANBglghkgBZQMEAgEFAAQg47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFWgCQIBAf8EBQEB/wEBhAMhAP8="
}
```

`tsq` is optional, with the same size and “must contain this digest” checks as `/api/stamp`. The body cap is the same (413 if the request is too large). A digest that is not 64 lowercase hex characters, bad JSON, or a bad `tsq` is HTTP 400. The success body is the same `{ "ots", "tsr", "errors" }` object; the MCP client treats that as success and shows `https://lightdrawer.org/r/<hash>`.

This path sends no CORS headers, the same as `/api/stamp`. The MCP client runs as a local server, so it does not need CORS.

The lane is off unless the Worker var `MCP_LANE` is `on`. When it is off, the response is HTTP 404 `{"error":"not found"}` so the MCP tool silently falls back to a browser link. Setting `mcp_lane=off` in the `ct_meta` table has the same effect immediately, without a redeploy.

When the lane is on, two kinds of limit apply.

The burst guard is `MCP_STAMP_LIMITER`: about 5 requests per 10 seconds, per address, per Cloudflare location. That limit is approximate. It is there so a short flood does not reach the public calendars and FreeTSA. It does not replace the hourly and daily caps. If the binding is missing, the open lane returns HTTP 503 `{"error":"stamp lane unavailable"}` and does not stamp. `/api/stamp` and the upgrade routes still allow the request when their own limiter binding is missing, which is how local development without those bindings works.

The designed caps for a public open lane, also the values in the committed `wrangler.jsonc`, are:

- `MCP_LIMIT_IP_HOUR` — 20 stamps per UTC hour from one address. Set a smaller number to be stricter. `0` turns this cap off. That is a deliberate operator choice.
- `MCP_LIMIT_GLOBAL_DAY` — 500 stamps per UTC day for the whole lane. Set a smaller number to be stricter. `0` turns this cap off. That is a deliberate operator choice.

If a var is missing or invalid, the code uses 20 and 500. The hosted site currently runs with both caps at `0` in its private deploy config. That is an operator decision. The recommended setting in this repository is 20 and 500, or stricter.

Hitting the burst guard or a cap that is turned on returns HTTP 429 `{"error":"Too many requests. Try again later."}` with a `Retry-After` header. The Worker also writes one warning line, `{"msg":"mcp stamp limited","scope":"mcp-burst"}` (or `mcp-ip`, or `mcp-global`). The line has no address, digest, or key. The MCP client then falls back to the browser.

Raw IP addresses are not stored. When the hourly cap is off, no per-address counter row is written at all. When it is on, a per-address counter is keyed by HMAC-SHA256 of the IP and the current UTC day. The HMAC key is the `MCP_IP_SALT` secret if present; otherwise it is derived from `CT_TICK_SECRET` with a domain-separation string so a deploy can run without an extra secret. Local development with neither secret uses a fixed dev-only string. Rows live only as long as they are needed (the current UTC hour for per-address counts, the current UTC day for the global total) and are deleted by the existing 15-minute cron.

`/api/stamp` is not changed: browsers still need Turnstile when it is configured, and trusted servers still use Bearer API keys.

### Upgrade requests (from `verify.html`, including `file://`)

OpenTimestamps, after the calendars have had time to land in Bitcoin (usually 1–6 hours):

```
GET /api/ots/upgrade?cal=https://alice.btc.calendar.opentimestamps.org&commitment=0123abcd...
```

- `cal` must be `https://` with no path or query, and the hostname must match the Worker's calendar allowlist.
- `commitment` is even-length hex (the pending calendar commitment, not your file).
- The Worker proxies `GET https://{host}/timestamp/{commitment}` and may cache a successful response at the edge for one hour. A 404 from the calendar is returned as `{ "pending": true }`.

Certificate-log stamp, after the next batch certificate has been issued (15-minute sub-batches; a certificate about every 6 hours):

```
GET /api/ct/upgrade?digest=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

- `digest` is the same 64-hex SHA-256 of `statement.json`.
- If no `CT_DB` binding is configured, the response is HTTP 404 `{ "pending": true }`. On the hosted deployment (lightdrawer.org; the workers.dev URL serves the same Worker) the binding is present, so a freshly stamped hash returns pending until its batch certificate is issued.
- If the digest is still waiting or its batch is not yet in a certificate, the same pending JSON is returned.
- When ready, the response is the anchored `proofs/ct.json` object (Merkle path, hostname, certificate PEM, optional SCTs, crt.sh URL).

Both upgrade endpoints send `Access-Control-Allow-Origin: *` so a receipt opened from `file://` can call them. `POST /api/stamp` does not: browser posts are same-origin only, and the endpoint still sends no CORS headers. A request that presents a valid API key is accepted without the origin check, so another server (for example a Worker) can stamp without being served from the same site. A browser page on another origin cannot use a key: there is no CORS preflight for `/api/stamp`.

### Public lookup link

`GET /r/<64-hex>` is a shareable page for a fingerprint LightDrawer has seen (for example from a QR code on a Fairview PDF). `GET /?digest=<64-hex>` responds with a 302 to that address. The page is written for regular people: it shows the fingerprint, whether LightDrawer has a record, a time, the certificate-log status, and how to check the full proof with `verify.html`. Technical fields are in a folded section. A missing record is HTTP 404 with the heading "No stamp found for this fingerprint"; a malformed hash is HTTP 400. `GET /api/lookup?digest=<64-hex>` (or the same `/r/` URL with `Accept: application/json`) returns the same facts as JSON. These responses send no CORS headers.

The time on the page is as honest as the stored data allows. While the digest is still in `ct_pending`, the exact `received_at` is shown as **First received**. After the digest is sealed into a sub-batch, `received_at` is deleted and only `ct_batches.opened_at` / `closed_at` remain — a 15-minute window that contained the original time — so the page says **Stamped no later than** the window close, and names the window in the text. The certificate-log status is pending until the batch has a stored certificate; then the page links to crt.sh for that batch hostname.

The fingerprint in the URL is whatever was posted to `/api/stamp`. For a receipt made on this site, that is `SHA-256(statement.json)`, not the hash of the original file alone.

### Stamp button for other websites

Other sites can link to LightDrawer with a plain HTML “Stamp this with LightDrawer” button. The public guide is `/button` (`web/ui/button.html`). The recommended snippet is a same-document `<a href="https://lightdrawer.org/">` with optional CSS — no JavaScript, and no third-party script loaded from LightDrawer on the host page.

Optional context:

- `GET /?expect=<64-hex>` — the host already knows the file’s SHA-256 (for example it published that hash next to a download). The homepage is still a static page; the Worker does not treat `expect` as a lookup. The browser compares the dropped file’s hash with `expect` and, on a mismatch, shows a warning and leaves “Get your receipt” disabled. Invalid values (anything other than 64 hex characters) are ignored and never written into the page as raw HTML.
- `#digest=<64-hex>` — an optional helper the host serves itself (`web/snippets/lightdrawer-stamp.js`, copied to `/lightdrawer-stamp.js` for download) hashes a chosen file with Web Crypto and opens the link’s `href` with that fragment. URL fragments are not sent to the server, so this hash does not appear in Worker or request logs. If both `expect` and `#digest=` are present and disagree, the fragment wins and the page also warns that the link is inconsistent.
- `GET /r/<64-hex>` — “Check this LightDrawer receipt.” The hex must be a receipt fingerprint (`SHA-256(statement.json)`), the same value used by the share link.

`/?digest=<64-hex>` remains the existing 302 to `/r/<digest>` and must not be used as a file-hash hint.

The helper never calls `/api/stamp` and never sends an API key. `/api/stamp` stays same-origin with no CORS headers. A Bearer API key is still only for a site’s own server (for example Fairview), not for JavaScript running in another page. Finishing a receipt still needs the original file on lightdrawer.org so `statement.json` can be built the usual way (`file → sha256 → statement.json → sha256 → proofs`). A pre-supplied file hash is treated as an expected fingerprint to confirm against, not as a substitute for dropping the file.

There is no `return=` parameter. Sending the browser back to an arbitrary host URL after a stamp would be an open redirect.

Snippet HTML uses no inline event handlers. Copy buttons on `/button` live in `web/ui/button.js` and the helper uses `addEventListener`, so both work under a Content-Security-Policy that forbids inline scripts.

### What never goes to LightDrawer

Optional Sigstore Rekor submission is done **by the browser, straight to** `https://rekor.sigstore.dev/api/v1/log/entries`. The Worker never sees that hash a second time. Rekor is off by default because the entry is public and permanent.

## 2. Each proof, step by step

### OpenTimestamps -> Bitcoin

1. The Worker posts your 32-byte statement hash to three public calendars.
2. Each calendar returns a detached, still-**pending** proof: we have this hash, and we will put it into a Bitcoin transaction.
3. The browser merges those answers into one `proofs/statement.json.ots`.
4. A few times a day the calendar operators batch thousands of hashes into one Bitcoin transaction (they pay the small fee). This usually completes in about 1–6 hours.
5. Later, `ots upgrade` or `verify.html` with upgrade ticked calls `/api/ots/upgrade`, which fetches the rest of the proof from the same calendar.
6. Once upgraded, verification follows the operations in the `.ots` file until it reaches a Bitcoin block Merkle root. Online checks ask public block explorers; offline checks can only confirm the proof structure and the claimed block height.

What this proves: the statement hash existed **no later than** that Bitcoin block's time (block times can be off by up to about two hours). After upgrade, you do not have to trust LightDrawer or the calendars — only Bitcoin.

### FreeTSA (RFC 3161)

1. The browser builds a `TimeStampReq` for the statement hash, with a random nonce and `certReq = true`.
2. The Worker forwards that request to `https://freetsa.org/tsr`.
3. FreeTSA returns a signed `TimeStampResp` (`proofs/statement.json.tsr`) whose `genTime` is the TSA's clock.
4. The verifier checks the token against the pinned FreeTSA root (`trust/freetsa-cacert.pem`) and, if present, the nonce stored in `receipt.json`.

What this proves: FreeTSA attests that the hash existed at `genTime`. You are trusting one timestamp authority and its key. This is checkable immediately, including offline with OpenSSL. Revocation (CRL/OCSP) is not checked offline.

### Optional Sigstore Rekor

1. If you tick the box, the browser creates a throwaway P-256 key, signs the statement, and POSTs a `hashedrekord` to Rekor.
2. Rekor returns an entry (uuid, `integratedTime`, signed entry timestamp, inclusion proof). That JSON is stored as `proofs/rekor-entry.json`.
3. The verifier checks the log id against the bundled Rekor public key, that the entry's hash equals `SHA-256(statement.json)`, the throwaway signature, the SET, and the Merkle inclusion proof.

What this proves: that hash was recorded in Sigstore's public log at `integratedTime`. It does not say who submitted it. The entry is public forever.

### Certificate-log stamp (Certificate Transparency)

This is the extra witness. It is **not** a replacement for Bitcoin.

1. **Queue.** When you stamp, the statement hash is eligible for the next batch. A fresh receipt contains `proofs/ct.json` with `"status": "pending"`. On a Worker with `CT_DB` bound, the hash is inserted into `ct_pending`. The Node prototype (`scripts/ct-anchor.mjs`) keeps the same queue in a local state file.
2. **Sub-batch (default every 15 minutes).** Due hashes in a time window are sorted, deduplicated, and hashed into an RFC 6962 Merkle tree:
   - leaf hash = `SHA-256(0x00 || 32-byte digest)`
   - interior node = `SHA-256(0x01 || left || right)`
   - the unpaired last node at a level is promoted (not hashed with itself)
   The tree root `R` is a SHA-256. The waiting-queue entry for each of those digests is removed (`state.pending` no longer lists them).
3. **Name encoding.** `R` becomes a DNS name with two hexadecimal labels (32 + 32 characters), each well under the 63-character label limit:

   `<first 32 hex chars of R>.<last 32 hex chars of R>.ct.lightdrawer.org`

   Hex is used instead of a single base32 label so the name is the same encoding already shown for fingerprints: anyone can split a SHA-256 in half and read it. The full name is 87 characters, under the 253-character DNS limit.
4. **Certificate (default every 6 hours, first one as soon as a sub-batch has closed).** Up to 100 of those names (Let's Encrypt's per-certificate identifier cap) are packed into one certificate as Subject Alternative Names. At 15-minute sub-batches and a 6-hour certificate, that is up to 24 names per certificate, so timestamp precision is finer than the certificate rate. About 4 certificates a day is about 28 a week, under Let's Encrypt's 50 new certificates per registered domain per 7 days (capacity refills at 1 certificate every 202 minutes; source: https://letsencrypt.org/docs/rate-limits/ , updated 5 August 2026), leaving about 22 a week for retries.
5. **DNS-01.** The Worker cron (`*/15 * * * *`) closes due sub-batches every 15 minutes. Certificate issuance is split into two phases so it fits Worker time limits: phase 1 creates the ACME order and writes TXT records; phase 2 (a later tick) finalizes the order, stores the certificate, and **deletes** those TXT records. The ACME directory is the `ACME_DIRECTORY` config var and defaults to Let's Encrypt **staging** (`https://acme-staging-v02.api.letsencrypt.org/directory`). Production directories are allowed by `src/ct-runtime.js` only when `CT_PRODUCTION=1` (the hosted lightdrawer.org site sets this and points `ACME_DIRECTORY` at `https://acme-v02.api.letsencrypt.org/directory`). A production ACME account key is stored separately from any staging account. `scripts/ct-anchor.mjs` still refuses production directories. Failed orders do not immediately retry: the Worker records the attempt and waits the same 6-hour interval before starting another, unless `force` is set. No website has to be hosted on the batch-root names. DNS writes use a Worker secret `CF_DNS_TOKEN` and are allowed only for names matching `_acme-challenge.<32hex>.<32hex>.ct.lightdrawer.org`. If that secret is not set, batches still close and wait; issuance is skipped. `POST /api/ct/tick` (Bearer `CT_TICK_SECRET`) can run the same job on demand; `{ "force": true }` also closes the current open window and bypasses the interval so an operator can finish issuance without waiting.
6. **Public witness.** Let's Encrypt embeds Signed Certificate Timestamps (SCTs) in the certificate and the certificate appears in public Certificate Transparency logs. Anyone can look the hostname up on crt.sh (the URL is stored in `ct.json`). An SCT is a log's signed promise that it saw the (pre)certificate at a given timestamp and will merge it into its tree within the log's maximum merge delay. Listed logs today still advertise an MMD of **24 hours** (86400 seconds, from the Chrome CT log list snapshot in `trust/ct-logs.json`). Chrome's current policy for newly applying logs is stricter (RFC 6962 logs at most 4 hours, static-ct-api logs at most 1 minute), but the "existed no later than" time is the SCT timestamp itself; the entry may take up to the MMD to show in a queryable tree.
7. **Upgrade.** `GET /api/ct/upgrade?digest=...` (or `node scripts/ct-anchor.mjs upgrade <digest>`) returns an anchored `proofs/ct.json`: the digest, Merkle path to `R`, the hostname, the certificate PEM, any SCTs we have, and the crt.sh URL. `verify.html` can fetch that the same way it upgrades an `.ots` file.
8. **Offline check.** The verifier recomputes `SHA-256(statement.json)`, walks the Merkle path to `R`, decodes the hostname back to `R`, and checks that the certificate's SAN list contains that hostname. If the certificate chains to a pinned public CA root (ISRG Root X1 / X2, bundled from Let's Encrypt) or an SCT signature verifies against a bundled CT log key, it treats the certificate `notBefore` and/or the SCT timestamp as "existed no later than." A PEM that merely claims the right SAN, without a trusted chain or verified SCT, is rejected. Precertificate SCTs (the kind Let's Encrypt embeds) are verified offline: the verifier reconstructs the precertificate TBSCertificate by removing the embedded SCT list extension, then checks each SCT against the bundled log keys in `trust/ct-logs.json` (a snapshot of Chrome's v3 log list, including static-ct-api tiled logs). A trusted CA chain is still checked as well. The snapshot is refreshed with `node scripts/refresh-ct-logs.mjs`; the verifier never fetches a log list at verify time.

## 3. What is stored server-side, and for how long

Stated against the code, not against a wish list.

| Place | What is stored | How long |
|---|---|---|
| Browser / receipt ZIP | The only full record: `statement.json`, proofs, cover page, `verify.html`. The original file is not copied into the ZIP. | You keep it. |
| `POST /api/stamp` handling | The JSON body (`digest`, `tsq`, optional Turnstile token) exists in memory for the request. | Dropped when the request ends. |
| OpenTimestamps calendars / FreeTSA / Rekor | Whatever those services retain about a hash they were sent. | Their policies, not ours. |
| Worker rate limiting | `src/worker.js` reads `CF-Connecting-IP` (or the string `local`) and passes `stamp:<ip>`, `upgrade:<ip>`, `ct-upgrade:<ip>`, or `mcp-stamp:<ip>` to Cloudflare's rate-limit binding (10/minute for stamp, 60/minute for upgrades, about 5 per 10 seconds per address per location for the MCP lane burst guard). A request that presents a Bearer header is first limited per IP with `stamp:auth:<ip>` (20/minute via `STAMP_AUTH_LIMITER`) before any D1 key lookup. A trusted caller authenticated with an API key then uses `stamp:key:<id>` instead of `stamp:<ip>`, still 10/minute, so one caller does not share the visitor IP bucket. The open MCP lane also counts stamps in D1 when a cap is on (20 per hashed IP per UTC hour and 500 per UTC day in the committed config, or stricter; `0` turns that cap off). | LightDrawer code does not write that IP to disk, a log file, or the receipt. A burst or cap refusal on the MCP lane logs only `{ msg, scope }` (`mcp-burst`, `mcp-ip`, or `mcp-global`). The rate-limit binding is Cloudflare's in-memory limiter. If `MCP_STAMP_LIMITER` is missing, the open lane returns HTTP 503. `/api/stamp` and the upgrade routes still allow the request when their limiter binding is missing. Cloudflare's own edge may retain request logs as part of running any Worker; that is outside this repository. |
| Worker `CT_DB` (D1 `lightdrawer-ct`) | `ct_pending(digest, received_at)` on stamp; closed batches, leaf lists, Merkle paths, issued certificate PEMs, and a small ACME account/issuance state so `/api/ct/upgrade` can answer and so a two-phase DNS-01 issuance can resume. `stamp_keys` holds API key hashes, labels, and optional revoke timestamps for trusted server callers — never the plaintext key. The public `/r/<digest>` page reads the same tables (never files or receipts). `mcp_lane_usage` holds counters for the open MCP stamp lane: a per-address hourly count keyed by HMAC-SHA256 of the IP and UTC day (never the raw IP) and a global daily count. `ct_meta` may also hold `mcp_lane=off` to disable that lane without a redeploy. | A digest is removed from `ct_pending` when it is sealed into a closed sub-batch, and `received_at` goes with it. After that, the lookup page can only honestly say the fingerprint was received in that batch's `opened_at`–`closed_at` window. The closed batch **keeps** its leaf list (the hashes that were in that window) so a later upgrade or lookup can still find it. LightDrawer does not currently delete those closed-batch records; deleting them would make late upgrades impossible. The file is never stored. The ACME account JWK lives in `ct_meta` so the Worker does not register a new Let's Encrypt account on every tick. A revoked stamp key stays in the table with `revoked_at` set so the same hash cannot be reused. MCP lane counter rows are deleted by the 15-minute cron once their hour or day bucket has expired. |
| `scripts/ct-anchor.mjs` state file (`build/ct-state.json` on the machine that runs it) | The same queue and batch records, for the prototype runner. | Pending queue entries are removed when the sub-batch closes. Batch leaf lists and issued certs remain so `upgrade` works. `build/` is gitignored. |

There are no accounts and no file uploads. Application observability (`wrangler.jsonc` has `observability.enabled`) may capture Worker traces if left on; those traces would see request metadata and the hash that was posted, not file bytes.

## 4. How to verify without our verifier

Work inside an extracted receipt directory. Replace `original.jpg` with your file.

```sh
# 1. The file in your hand is the file in the receipt
sha256sum original.jpg
# Must equal the "sha256" field inside statement.json

# 2. Every proof is about statement.json, not the file directly
sha256sum statement.json
# Must equal receipt.json "statement_sha256" and proofs/ct.json "digest"
```

RFC 3161 (needs `trust/freetsa-cacert.pem` and `trust/freetsa-tsa.crt`, or copies you download yourself from https://freetsa.org/files/ ):

```sh
openssl ts -verify -data statement.json \
  -in proofs/statement.json.tsr \
  -CAfile trust/freetsa-cacert.pem \
  -untrusted trust/freetsa-tsa.crt
```

OpenTimestamps:

```sh
pip install opentimestamps-client
ots upgrade proofs/statement.json.ots
ots verify -f statement.json proofs/statement.json.ots
```

`ots verify` wants a Bitcoin node or will use the public calendar/explorers the client is configured for. "Pending" means Bitcoin has not confirmed yet.

Rekor, if `proofs/rekor-entry.json` exists:

```sh
# uuid is also in receipt.json under proofs.rekor.uuid
curl https://rekor.sigstore.dev/api/v1/log/entries/<uuid>
# The entry's hashedrekord data.hash.value must equal sha256sum statement.json
```

Certificate-log proof, if `proofs/ct.json` has `"status": "anchored"`:

```sh
# Print the crt.sh lookup URL stored in the proof
python3 -c "import json; print(json.load(open('proofs/ct.json'))['crtsh_url'])"
# Open that URL and confirm a certificate was issued for exactly that hostname.

# Extract the leaf certificate and read its names and notBefore
python3 -c "import json; open('/tmp/lightdrawer-ct.pem','w').write(json.load(open('proofs/ct.json'))['certificate_pem']); print(json.load(open('proofs/ct.json'))['hostname'])"
openssl x509 -in /tmp/lightdrawer-ct.pem -noout -dates -ext subjectAltName
# subjectAltName must include the hostname; hostname must be
# <root[0:32]>.<root[32:64]>.ct.lightdrawer.org
```

Recompute the Merkle root by hand (RFC 6962, same math as the verifier):

```sh
python3 -c "
import json, hashlib, binascii
ct = json.load(open('proofs/ct.json'))
digest = hashlib.sha256(open('statement.json','rb').read()).hexdigest()
assert digest == ct['digest'], (digest, ct['digest'])

def sha(b):
    return hashlib.sha256(b).digest()
leaf = sha(b'\\x00' + binascii.unhexlify(digest))

def largest_pow2_lt(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k

def root_from_path(leaf_hash, index, tree_size, path):
    if tree_size == 1:
        return leaf_hash
    k = largest_pow2_lt(tree_size)
    if index < k:
        left = root_from_path(leaf_hash, index, k, path)
        right = path.pop(0)
        return sha(b'\\x01' + left + right)
    right = root_from_path(leaf_hash, index - k, tree_size - k, path)
    left = path.pop(0)
    return sha(b'\\x01' + left + right)

path = [binascii.unhexlify(x) for x in ct['merkle']['path']]
got = root_from_path(leaf, ct['merkle']['leaf_index'], ct['merkle']['tree_size'], path)
assert path == [], 'unused path hashes'
assert got.hex() == ct['merkle']['root']
host = ct['hostname'].lower()
root = ct['merkle']['root']
assert host == root[:32] + '.' + root[32:] + '.ct.lightdrawer.org'
print('Merkle path OK; hostname encodes the root:', host)
"
```

Or skip the command line and open `verify.html` (it works from `file://` and sends nothing unless you opt in to online checks / upgrade). The file:// default upgrade proxy is `https://lightdrawer.org` (`DEFAULT_UPGRADE_PROXY` in `web/ui/verify-ui.js`). Self-hosters can point that constant at their own workers.dev or custom domain.

## 5. What it cannot prove, and what happens if something disappears

A receipt proves that **a file with this SHA-256, plus this statement, existed no later than the stamped times.** It does not prove who made the file, who stamped it, that the file is authentic or unedited *before* you hashed it, that the notes are true, or that what the file depicts is true. Provenance fields are the collector's own statements, frozen in time by the stamps.

| If this goes away | What still works | What breaks |
|---|---|---|
| LightDrawer website / Worker | Every already-downloaded receipt, `verify.html` inside it, `sha256sum`, `openssl ts -verify`, `ots verify` after you have an upgraded `.ots`. | New stamps; OTS upgrade through our proxy (you can still talk to calendars with the `ots` client); CT upgrade through `/api/ct/upgrade` (you can still look the hostname up on crt.sh if you already have an anchored `ct.json`). |
| OpenTimestamps calendars | Already-upgraded Bitcoin proofs. Pending proofs that were never upgraded may never finish. | New OTS stamps and upgrades of still-pending proofs. |
| Bitcoin | Nothing else gives the same "no trusted party" property. | Confirming an upgraded `.ots` against the chain. |
| FreeTSA | Other proofs in the same receipt. | Checking the `.tsr` (unless you already trust a locally saved token and the pinned root). |
| Rekor | Other proofs. The public entry may still be mirrored. | Looking up or verifying that optional entry. |
| Let's Encrypt, or the DNS zone for `lightdrawer.org` | Already-issued certificates remain in CT logs and archives. Pending CT proofs never get a certificate. | New certificate-log stamps. |
| A particular CT log shard | Other logs that also received the certificate; crt.sh and similar archives often keep copies. Logs are temporally sharded (often by year of certificate expiry) and retired shards may eventually stop answering queries. Chrome encourages operators to keep retired logs available but does not require it. | Querying that shard directly after it is retired. |
| Your original file | The receipt still proves *a* hash existed. | Tying the receipt to any readable content. Changing one bit of the file changes the hash. |

The certificate-log stamp depends on Let's Encrypt remaining willing to issue and on public logs/archives remaining readable. That is why it is documented as an extra witness, not as a replacement for the Bitcoin proof.

## 6. Third-party services and their roles

| Service | Role in a receipt | What it sees | Do you have to trust it forever? |
|---|---|---|---|
| Your browser | Hashes the file, builds the statement and ZIP, verifies offline | The file, locally | You are running it |
| LightDrawer Worker | Relays the 32-byte hash to calendars and FreeTSA; optional CT queue; OTS/CT upgrade proxy; open MCP stamp lane | The hash, the RFC 3161 request, your IP (for rate limits only; the MCP lane stores only a keyed hash of the IP, never the raw address). For a server-to-server stamp, the caller's key label is logged, not written into the receipt. | No, once you have the receipt (and an upgraded `.ots` / anchored `ct.json`) |
| OpenTimestamps calendars (opentimestamps.org, Eternity Wall, and others) | Accept the hash; later put a batch of hashes into Bitcoin | The hash | After Bitcoin confirmation and upgrade, no |
| Bitcoin | Public, ordered ledger whose block headers time the upgraded `.ots` | A batch commitment, not your file | This is the trust-minimized backbone |
| FreeTSA (freetsa.org) | RFC 3161 timestamp authority | The hash (inside the timestamp request) | Yes, you trust its key; the pinned root is in `trust/` |
| Sigstore Rekor | Optional public artifact log | The hash and a throwaway signature | You trust Rekor's log key; the entry is public |
| Let's Encrypt | Issues the batch-root certificate. The hosted lightdrawer.org site uses production ACME (`CT_PRODUCTION=1`). Staging remains the code default for self-hosters; staging certificates chain to a test CA (the offline verifier flags that chain as untrusted/test). `scripts/ct-anchor.mjs` still refuses production directories. | The hash-named hostnames, via DNS-01 | You trust that a publicly logged LE certificate is hard to forge; CT logs back that up |
| Cloudflare DNS | Temporary `_acme-challenge` TXT records for DNS-01, only under `ct.lightdrawer.org` | Those TXT values, not your file | Only during issuance; records are deleted afterwards |
| Certificate Transparency logs (Google, Cloudflare, DigiCert, Let's Encrypt Oak, and others) | Public append-only logs of the certificate; SCTs are the signed "we saw this" receipts | The certificate, whose SAN is the batch root, not your individual file hash | The bundled log keys in `trust/ct-logs.json` are a snapshot of Chrome's v3 list (RFC 6962 and tiled logs); logs shard and can retire |
| crt.sh (and similar archives) | Convenient lookup of logged certificates | Public CT data | Convenience; the certificate in `ct.json` is the copy you keep |
| Cloudflare (hosting) | Serves the site and Worker; Turnstile if you enable it; rate-limit binding | Request metadata; hash on `/api/stamp` | Operational, not a proof authority |
| Cloudflare Turnstile | Optional human check on `/api/stamp` | The widget token | Not part of the proof |

LightDrawer does not invent hashing or timestamps. It packages these existing pieces into one receipt with a plain-language cover page and an offline checker.
