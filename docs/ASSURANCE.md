# Security assurance case

This document explains why we believe LightDrawer meets its security requirements. It is the project's own argument, with links to the code and tests behind each point, so you can check it. It is not an audit, a certification, or a statement of legal compliance. If you find a gap, please report it privately as described in [SECURITY.md](../SECURITY.md).

Related reading:
- [HOW-IT-WORKS.md](../HOW-IT-WORKS.md): the long technical description.
- [docs/TRUST.md](TRUST.md): the controls in place and the repository settings.
- [README: what it proves / what it does not](../README.md#what-it-proves--what-it-does-not).

## 1. What LightDrawer must do (security requirements)

1. **The file stays on the device.** Only a SHA-256 fingerprint of a small `statement.json` (which itself contains the file's SHA-256) is sent to the server. File bytes, names, and notes are not sent.
2. **A receipt can be checked without trusting LightDrawer.** Each proof is checkable with public tools (`sha256sum`, `openssl ts -verify`, `ots verify`, crt.sh) and with the offline checker `verify.html` inside the receipt.
3. **Verification fails closed.** A changed file, a changed statement, or a tampered or mismatched proof must not be reported as a match.
4. **The service can't easily be abused.** The stamp, upgrade, and lookup routes must not become an open relay, a request forwarder to arbitrary hosts, or a way to flood upstream witnesses or the database.
5. **Little data is kept.** There are no accounts, no file storage, and no stored IP addresses.
6. **The software that ships is the software in the repository.** Changes are reviewed through pull requests and tested, and release files carry signed build provenance.

What LightDrawer does **not** claim is listed in [HOW-IT-WORKS.md section 5](../HOW-IT-WORKS.md#5-what-it-cannot-prove-and-what-happens-if-something-disappears). A receipt shows that a file with a given fingerprint existed by a time. It does not show who made the file, or that its content is true.

## 2. Threat model

| Who | What they might try | Main defenses |
|---|---|---|
| Someone forging or backdating a receipt | Edit a file or a `statement.json` after stamping. Swap in a different proof. Claim an earlier time. | Every proof covers `SHA-256(statement.json)`, and the statement carries the file's SHA-256. Times come from independent witnesses (Bitcoin through OpenTimestamps, an RFC 3161 timestamp authority, Certificate Transparency logs), not from LightDrawer. The verifier checks signatures against pinned trust anchors in [`trust/`](../trust/). |
| A malicious or compromised LightDrawer server | Return fake proofs. Learn file contents. | The server only ever sees a fingerprint. Proofs are signed or anchored by third parties and checked on the user's side. A fake proof fails verification. |
| An abuser of the public API | Use `/api/stamp` as an open relay to FreeTSA. Use the upgrade proxies to reach arbitrary hosts (SSRF). Flood stamps or API-key guesses. Send oversized bodies. | Strict input checks and allowlists, rate limits, body size limits, and a human check or a hashed API key (section 5, item 6). |
| A web attacker | Script injection, clickjacking, content sniffing, cross-origin posts. | A strict Content Security Policy, `X-Frame-Options: DENY` and `frame-ancestors 'none'`, `nosniff`, HSTS, and a same-origin check on browser stamp requests ([`web/ui/_headers`](../web/ui/_headers)). Untrusted text is set as text, not as HTML. |
| A supply-chain attacker | A malicious dependency or Action, a moved tag, a tampered release file. | The runtime has no npm dependencies. Dev dependencies are locked in `package-lock.json` and watched by Dependabot. Actions are pinned to commit SHAs. Releases carry Sigstore attestations and SLSA Build Level 3 provenance ([SECURITY.md: Verifying a release](../SECURITY.md#verifying-a-release)). |
| A witness going away | Bitcoin calendars, FreeTSA, or a CT log becomes unavailable. | Each receipt holds several independent proofs. The section 5 table in HOW-IT-WORKS lists what still works if each one disappears. |

## 3. Trust boundaries

1. **The user's device and browser.**
   - The file is read and hashed here, in 4 MB chunks ([`web/lib/46-sha256.js`](../web/lib/46-sha256.js)).
   - `statement.json` is built here, and the receipt ZIP is assembled here ([`web/lib/80-receipt.js`](../web/lib/80-receipt.js)).
   - Nothing about the file crosses this boundary except one 32-byte fingerprint.
2. **Browser → the LightDrawer Worker** (a Cloudflare Worker, [`src/worker.js`](../src/worker.js)).
   - All input from the browser is untrusted.
   - The Worker accepts a fingerprint and an RFC 3161 request for that same fingerprint, validates both, and forwards only those bytes to the witnesses.
3. **Worker → the D1 database.** The Worker stores:
   - pending and batched fingerprints for the certificate-log witness;
   - SHA-256 hashes of server-to-server API keys, never the keys;
   - short-lived de-duplication rows;
   - lane counters keyed by an HMAC of the IP address, never the address itself.

   File bytes and IP addresses are not stored. All queries use bound parameters.
4. **Worker → third-party witnesses.**
   - OpenTimestamps calendars (Bitcoin), FreeTSA (RFC 3161), Let's Encrypt and the public Certificate Transparency logs, and optionally Sigstore Rekor.
   - All of these are reached over HTTPS, and the Worker calls only fixed or allowlisted hosts.
   - Their answers are not trusted by themselves. They are verified later, on the user's side.
5. **The offline verifier (`verify.html`).**
   - A single HTML file with all its code inlined, under its own strict CSP. It is shipped inside every receipt.
   - It needs no network to check a receipt.
   - Network use is opt-in: Bitcoin block lookups at public explorers, and upgrade requests to the Worker, which may come from `file://`.
6. **The repository and CI/CD → the users.**
   - Code reaches `main` only through pull requests with a passing required test check.
   - Releases are built by the release workflow from a tag.
   - Deploys to the hosted site use a scoped deploy token, not an interactive login.

## 4. Secure design principles applied

These follow Saltzer and Schroeder's design principles.

- **Economy of mechanism.**
  - The browser code is plain scripts concatenated by one small build script ([`scripts/build.mjs`](../scripts/build.mjs)), with no bundler and no runtime dependencies.
  - The server is one Worker.
- **Fail-safe defaults.**
  - A receipt is shown as a match only when the file hash and statement hash agree and no proof check fails. Proofs that are still pending are shown as pending, not as confirmed. Property tests check that a broken statement fails closed ([`test/property.js`](../test/property.js)).
  - The certificate-log witness uses Let's Encrypt staging unless production is explicitly turned on.
  - The open MCP lane returns HTTP 503 if its rate limiter is missing, rather than running unlimited.
  - Redirects from upgrade targets are refused.
- **Complete mediation.**
  - Every stamp request goes through the same checks: body size, input validation, rate limit, and a human check or a valid API key.
  - The scheduled certificate job's HTTP trigger needs a secret that is compared in constant time.
- **Open design.** All code, formats, and verification steps are public. Security does not depend on keeping the design secret.
- **Separation of privilege.**
  - A receipt holds several independent witnesses, so no single party (including LightDrawer) can make a receipt check out by itself.
- **Least privilege.**
  - CI runs with read-only repository permissions, and only specific jobs get token or attestation permissions.
  - The DNS token is meant to be scoped to DNS edits on the one zone the certificate witness uses (see the README's self-hosting notes).
  - The deploy token is used only for deploys.
- **Least common mechanism.**
  - The open MCP lane has its own limits and its own kill switch, so trouble there does not affect browser stamps.
- **Psychological acceptability.**
  - The site explains in plain language what a receipt proves and what it does not.
  - Checking is one drop of a file into `verify.html`.

## 5. How common weaknesses are countered

These are mapped to OWASP Top 10 and CWE classes.

1. **Injection (CWE-89, CWE-79).**
   - Database queries use prepared statements with bound parameters.
   - In the browser, text from receipts and lookups is set with `textContent`. The server-rendered receipt lookup page escapes values before putting them in HTML ([`src/receipt-lookup.js`](../src/receipt-lookup.js)).
   - The CSP blocks inline and third-party scripts on the main site.
2. **SSRF and open-relay use (CWE-918).**
   - The OpenTimestamps upgrade proxy accepts only `https://` calendar hosts on an allowlist, with no path or query.
   - It does not follow redirects ([`test/api-hardening.mjs`](../test/api-hardening.mjs)).
   - The stamp route forwards only an RFC 3161 request of at most 256 bytes that contains the same 32-byte digest.
3. **Improper input validation (CWE-20).**
   - Digests must be exactly 64 lowercase hex characters ([`src/receipt-lookup.js`](../src/receipt-lookup.js)).
   - Bodies are size-limited, and JSON shapes are checked.
   - The parsers for DER, ZIP, OpenTimestamps, and certificate data check lengths and bounds and throw on bad input. Property tests exercise them with random input.
4. **Broken authentication and brute force (CWE-287, CWE-307).**
   - API keys are random secrets stored only as SHA-256 hashes, compared in constant time ([`src/stamp-keys.js`](../src/stamp-keys.js)).
   - Bearer attempts are rate-limited per IP before any database lookup.
   - Browser stamps need a Cloudflare Turnstile human check when one is configured.
5. **Cryptographic failures (CWE-327, CWE-295).**
   - The defaults are SHA-256 and standard signature algorithms, checked with WebCrypto.
   - Older hash operations appear only where an existing OpenTimestamps proof contains them.
   - TLS is handled by the platform with certificate checking on.
   - Trust anchors are pinned in `trust/`, and the build prints the pinned FreeTSA root fingerprint.
6. **Resource exhaustion (CWE-400, CWE-770).**
   - Per-IP and global rate limits apply.
   - A repeat-stamp cooldown reuses cached witness answers for the same digest.
   - Large files are hashed in chunks, and only the first 16 MB are scanned for Content Credentials.
7. **Sensitive data exposure (CWE-200, CWE-532).**
   - The stamp log line records the route, the status, and which entrance handled a request, but not the digest, the IP address, or the key. Platform request traces, if turned on, can see request metadata and the posted hash ([HOW-IT-WORKS section 3](../HOW-IT-WORKS.md#3-what-is-stored-server-side-and-for-how-long)).
   - The certificate tick route does not return exception text. Failures are logged on the server instead.
   - Secrets are platform secrets and are kept out of the repository. Secret scanning with push protection is on.
8. **Security misconfiguration.**
   - Hardening headers are set for every page ([`web/ui/_headers`](../web/ui/_headers)).
   - Repository protections are listed in [docs/TRUST.md](TRUST.md#repository-settings).
9. **Vulnerable components and software integrity (CWE-1104, CWE-494).**
   - Dependabot is on, Actions are pinned, CodeQL and OpenSSF Scorecard run, and releases carry signed provenance.
10. **Insufficient testing.**
    - `npm test` runs on every pull request and push to `main`, and the merge rule requires it.
    - It includes known-answer fixtures, tamper tests, API hardening tests, and property-based tests.
    - `npm run lint` runs ESLint on the server code, scripts, and tests.

## 6. Known limits

These are listed in the README under [Limits / known gaps](../README.md#limits--known-gaps):

- C2PA data is read but not validated.
- FreeTSA revocation is not checked offline.
- The certificate-log witness depends on Let's Encrypt and on the public logs staying readable.
- Live Rekor submission was not exercised.

LightDrawer has one maintainer (see [GOVERNANCE.md](../GOVERNANCE.md)). Code review today is the maintainer's own review plus the automated checks, not review by a second person.

## Keeping this current

When a change affects a requirement, a trust boundary, or one of the defenses above, update this file in the same pull request.
