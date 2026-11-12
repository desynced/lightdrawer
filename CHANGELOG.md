# Changelog

Every change to LightDrawer that affects what it does, how it's run, or how safe it is gets listed here, newest first. Dates are US Central time.

The code history is in the [commit log](https://github.com/desynced/lightdrawer/commits/main). Changes to how the live site at lightdrawer.org is run, which aren't code, are listed under **Operations** so nothing is hidden.

Version numbers follow [Semantic Versioning](https://semver.org): new features raise the middle number, and fixes raise the last.

## [1.6.0] - 2026-11-12

### Added
- Every finished `POST /api/stamp` and `POST /api/mcp/stamp` request writes one JSON log line. The line names the path, the HTTP status, which entrance handled it (`mcp` for the open lane, `key` after a valid API key, `turnstile` after a browser human check passed), and which cap stopped it (`burst`, `ip`, `global`, `dedup`, or `false` when none of those did). A request that stops before a valid key or a passed human check is still logged, with `via` set to null. The line does not include the API key, the key id, the label, the file hash, or the IP address. Errors are included, including HTTP 4xx and 429.
- A log warning when the open lane returns too many HTTP 429s in the current UTC minute. `MCP_ALARM_429_PER_MIN` sets the count (default 20). `0` turns the warning off. The Worker writes `{ "msg": "mcp-lane-alarm", "reason": "429-spike", "count": n }` at most once per minute on each isolate. It does not send email or Slack. The count stays in memory on that isolate and is not written to D1. The README explains how to read both lines in Cloudflare Workers Logs.

## [1.5.1] - 2026-11-12

### Changed
- The example Worker config now shows the recommended caps for a public open MCP lane: 20 stamps per hashed IP per UTC hour (`MCP_LIMIT_IP_HOUR`) and 500 stamps per UTC day for the whole lane (`MCP_LIMIT_GLOBAL_DAY`). A public lane should use those numbers or smaller ones. `0` still means that cap is off. Setting `0` is a deliberate operator choice. When a cap is off, LightDrawer writes no counter row for it. When a cap is on, the counter is still only a keyed hash of the address for the current UTC day, and the 15-minute cron still deletes expired rows.
- The MCP burst limit is about 5 requests per 10 seconds per address per location, and it is approximate. It sits in front of the hourly and daily caps. Those caps are the lasting limits.

### Fixed
- If `MCP_STAMP_LIMITER` is not bound, `POST /api/mcp/stamp` returns HTTP 503 instead of accepting the stamp. `/api/stamp` and the upgrade routes still allow a request when their own limiter binding is missing, which is how local development works today.

### Added
- A refused MCP stamp (HTTP 429 from the burst limiter or an hourly or daily cap) writes one Worker warning: `{"msg":"mcp stamp limited","scope":"mcp-burst"}`, or `mcp-ip`, or `mcp-global`. The line has no IP address, digest, or key.

### Notes
- This change does not deploy and does not edit the live site's settings. The hosted lane currently runs with both caps at `0` in its private config.

## [1.5.0] - 2026-11-12

### Added
- A same-digest upstream cooldown for `POST /api/stamp` and `POST /api/mcp/stamp`. After a successful stamp, repeating the same SHA-256 within the window reuses the cached calendar payloads instead of calling OpenTimestamps again. A cached stamp that has no TSR still calls FreeTSA when the request includes a valid `tsq`; a returned TSR is stored on that row without changing `last_ok_at`, so the calendar cooldown is not extended. If that FreeTSA call fails, the response is still HTTP 200 with the cached `ots`, `"tsr": null`, and a FreeTSA error. A request with no `tsq` receives the cached row as stored, including a TSR when one is already there. Configure with `STAMP_DEDUP_MS` (milliseconds; default `3600000` / 1 hour). `0` turns the cooldown off. Only the digest and those proof bytes are stored in D1 (`stamp_dedup`); never file contents or raw IPs. If the cooldown is still active but no cached body is available, the response is HTTP 429 with `Retry-After`. Website Turnstile and API-key checks are unchanged and still run first on `/api/stamp`.

## [1.4.0] - 2026-11-10

### Added
- An open stamp lane at `POST /api/mcp/stamp` for the [LightDrawer MCP server](https://github.com/desynced/lightdrawer-mcp) and similar local tools. It accepts the same hash-only body as `/api/stamp` (`digest` and optional `tsq`), with no human check and no API key. Website stamping and API-key stamping are unchanged.
- The lane can be switched off with the `MCP_LANE` variable (HTTP 404, so MCP clients fall back to the browser) or immediately, without a redeploy, by setting `mcp_lane=off` in the `ct_meta` table.
- Optional hourly and daily caps (`MCP_LIMIT_IP_HOUR` and `MCP_LIMIT_GLOBAL_DAY`). `0` means that cap is off (unlimited); a positive number turns it on. When a cap is off, no counter row is written for it, so no hashed-IP data is stored. The hosted site starts with both caps off. A short burst limit (5 requests per 10 seconds) sits in front to protect the public calendars and FreeTSA. If a cap or the burst guard is hit, the response is HTTP 429 with `Retry-After`.
- When an hourly cap is on, addresses are stored only as a keyed hash for the current UTC day, never as raw IPs. Those counters are removed by the existing 15-minute cron once they expire.

## [1.3.1] - 2026-11-10

### Fixed
- The offline verifier now checks Let's Encrypt's embedded precertificate SCTs against bundled Certificate Transparency log keys, instead of warning that the signature did not match. The bundled list also includes current static-ct-api (tiled) logs such as IPng Gouda, which the previous snapshot skipped. Refresh the snapshot with `node scripts/refresh-ct-logs.mjs`; verification itself stays offline.

### Changed
- The three example receipts in `examples/` were remade with the current LightDrawer. Each now includes the finished Bitcoin proof, the FreeTSA timestamp, and the certificate-log proof, and the README links to each one's public receipt page.

## [1.3.0] - 2026-11-10

### Added
- Websites can add a free “Stamp this with LightDrawer” link or a small helper they host themselves. A plain-language guide is at `/button`, with a standalone demo in `examples/stamp-button/`. The usual version is a normal HTML link. An optional `?expect=` query (the file’s SHA-256) makes LightDrawer warn if a different file is dropped; an optional helper can pass that same file hash in the URL fragment (`#digest=…`) so it never reaches a server log. Visitors still confirm the file and complete the human check on LightDrawer. Embedded pages do not call `/api/stamp`, and API keys stay on site servers only.

## [1.2.2] - 2026-11-10

### Changed
- Stamp requests now cap the request body by counting the bytes actually read, even if `Content-Length` is missing.
- JSON API responses now send a tight Content-Security-Policy (`default-src 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `frame-ancestors 'none'`.
- The on-demand certificate-log tick endpoint compares its secret in constant time (by hashing both values first) and is rate-limited per address, using an existing limiter with its own key.
- Stamp error lists no longer include raw messages from OpenTimestamps, FreeTSA, or the database. Those details stay in Worker logs.
- A leftover certificate-issuance error note in the database is cleared after a certificate is issued successfully.

### Added
- A `/.well-known/security.txt` file that points vulnerability reports at this repository's GitHub security advisories.

### Operations
- The Worker's default workers.dev address was turned off, so the production site is only reached through lightdrawer.org (and www).
- The site's minimum TLS version was raised to 1.2.
- The site's SSL mode was set to Full (strict).
- www.lightdrawer.org now redirects permanently to lightdrawer.org.

## [1.2.1] - 2026-11-10

### Added
- A plain-language "Why would I use this?" section on the homepage, with three everyday examples: showing you made something first, recording a rental's condition before a repair or move-out, and keeping the exact version of an agreement.

## [1.2.0] - 2026-11-09

### Added
- A shareable receipt page at `https://lightdrawer.org/r/<fingerprint>`. Anyone with the link can see whether a fingerprint was stamped and when, without trusting LightDrawer. The page shows only the fingerprint and its timestamps, never a file.
- `/?digest=<fingerprint>` now redirects to the receipt page. The same lookup is available as JSON.

### Notes
- While a stamp waits to be batched, the page shows its exact received time. After it's sealed into a Certificate Transparency batch, the page says "Stamped no later than" the batch's closing time, because the exact time isn't kept after batching.

## [1.1.0] - 2026-11-09

### Added
- An optional API key for trusted servers, so another service can stamp fingerprints without a browser human check. Only a hash of each key is stored. Each key has its own rate limit and can be revoked on its own. Receipts never name the caller, and requests without a key work exactly as before.

### Operations
- HTTP Strict Transport Security (HSTS) turned on, so browsers always use a secure connection.
- "Always Use HTTPS" turned on, so plain-http links redirect to https.
- A firewall rate limit added on the stamping endpoint (at most 5 requests per 10 seconds from one address), on top of the Worker's own limits.

### Changed
- Commit history was rewritten once to replace a personal email address in the commit author field with a private GitHub address. The code was unchanged.

## [1.0.0] - 2026-11-09

### Added
- First public release, live at lightdrawer.org.
- Files are fingerprinted (SHA-256) in your browser and never uploaded.
- Each fingerprint is anchored three ways: OpenTimestamps (Bitcoin), an RFC 3161 timestamp token, and Certificate Transparency (production Let's Encrypt certificates, issued every 6 hours).
- One readable receipt plus `verify.html`, a verifier that works offline.
- Free, with no account.
