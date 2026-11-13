# How we keep LightDrawer trustworthy

LightDrawer is not SOC 2 or otherwise certified. This page lists the controls that are actually in place, so you can check them yourself.

## What you can check

- **Your file stays on your computer.** The site hashes the file in the browser and does not upload it. [How it works](../README.md#how-it-works).
- **The code is public.** LightDrawer is open source under the [MIT license](../LICENSE).
- **You can report a security problem in private.** [SECURITY.md](../SECURITY.md) tells you how. Write to security@lightdrawer.org, or open a [private GitHub advisory](https://github.com/desynced/lightdrawer/security/advisories/new). There is no bounty.
- **The site publishes a security contact.** [/.well-known/security.txt](https://lightdrawer.org/.well-known/security.txt) points at those same private advisories. The copy in this repo is [web/ui/.well-known/security.txt](../web/ui/.well-known/security.txt).
- **Tests run on every change.** GitHub Actions runs the offline test suite on every pull request and every push to main. [ci.yml](../.github/workflows/ci.yml).
- **Dependencies get update requests.** Dependabot opens weekly pull requests for npm packages and for GitHub Actions. [dependabot.yml](../.github/dependabot.yml).
- **The automation is pinned.** Every Action in the workflows is pinned to a full commit SHA, with the version written next to it. A moved tag cannot swap in different code. [.github/workflows](../.github/workflows).
- **An outside score is published.** [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/desynced/lightdrawer/badge)](https://scorecard.dev/viewer/?uri=github.com/desynced/lightdrawer) [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/desynced/lightdrawer) checks this repository. The badge updates after the [Scorecard workflow](../.github/workflows/scorecard.yml) has published a result.
- **Release files can be checked.** When a version tag is pushed, the [release workflow](../.github/workflows/release.yml) builds the files and GitHub signs a provenance statement for them. [Verifying releases](../README.md#verifying-releases) is the short version of how to check.
- **Changes are written down.** The [changelog](../CHANGELOG.md) lists what changed in the software. Its **Operations** section lists changes to how the live site is run, which are not code.
- **A receipt does not require trusting us.** Three public witnesses record the fingerprint: [OpenTimestamps](https://opentimestamps.org) (Bitcoin), an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp authority (FreeTSA), and public [Certificate Transparency](https://certificate.transparency.dev) logs. Each receipt includes an offline checker, `verify.html`, so the check still works if this website is gone. [Verify without LightDrawer](../README.md#verify-without-lightdrawer).

## Technical detail

Hashing uses SHA-256 in the browser, in 4 MB chunks, so the file bytes are not sent to the Worker. What is stored, and for how long, is described in [HOW-IT-WORKS.md](../HOW-IT-WORKS.md).

The CI workflow checks out the repo with credentials persistence turned off, installs from `package-lock.json` with `npm ci`, and runs `npm test` (`node scripts/build.mjs && node test/run.mjs`) on Node 20. It does not run `test/e2e_browser.py` or `npm run test:live`.

Dependabot groups minor and patch updates for npm and for GitHub Actions, and keeps at most five open update pull requests for each. The workflow files pin `actions/checkout`, `actions/setup-node`, `actions/upload-artifact`, `actions/attest-build-provenance`, `ossf/scorecard-action`, and `github/codeql-action/upload-sarif` to a 40-character commit SHA.

Scorecard runs on a push to `main`, every Saturday, and on the `branch_protection_rule` event. The job publishes results (`publish_results: true`) and uploads the SARIF file to code scanning. The workflow's own permissions are read-only except for `security-events: write` and `id-token: write` on that job.

The release workflow runs only when a tag matching `v*` is pushed. After the same offline tests, it builds `lightdrawer-<tag>.tar.gz` containing `public/`, `build/core.js`, `src/`, `migrations/`, `schema/`, `trust/`, `package.json`, `package-lock.json`, `wrangler.jsonc` (the committed template, placeholders only), `LICENSE`, `README.md`, and `CHANGELOG.md`. `SHA256SUMS.txt` covers that tarball and a standalone `verify.html`. `actions/attest-build-provenance` signs those two files with GitHub's keyless OpenID Connect certificate (Sigstore). The three files are attached to the GitHub Release for that tag, and the notes are the matching changelog section when one exists. Check them with:

```sh
sha256sum -c SHA256SUMS.txt
gh attestation verify lightdrawer-vX.Y.Z.tar.gz --repo desynced/lightdrawer
```

A successful check proves the file was built by this repo's GitHub workflow from that tag. Tags `v1.0.0` through `v1.4.0` were pushed before this workflow existed, so they do not have that statement. Versions 1.5.0 through 1.6.1 are in the changelog and in `package.json` and are not tagged yet.

The offline checker is built into `public/verify.html` from `web/ui/verify.html`. It can check a receipt from a local file. It does not need this website unless you opt in to an online upgrade.

## Repository settings

These settings live in GitHub, not in this repository. This page cannot turn them on, and it does not claim they are already on. Confirm each one before you rely on it:

- [ ] Dependabot alerts and security updates
- [ ] Secret scanning with push protection
- [ ] Private vulnerability reporting
- [ ] A ruleset protecting `main` (pull requests required, CI must pass, no force-push or deletion)
