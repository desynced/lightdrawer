# Changelog

Every change to LightDrawer that affects what it does, how it's run, or how safe it is gets listed here, newest first. Dates are US Central time.

The code history is in the [commit log](https://github.com/desynced/lightdrawer/commits/main). Changes to how the live site at lightdrawer.org is run, which aren't code, are listed under **Operations** so nothing is hidden.

Version numbers follow [Semantic Versioning](https://semver.org): new features raise the middle number, and fixes raise the last.

## [Unreleased]

Nothing yet.

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
