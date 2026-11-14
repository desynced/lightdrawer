# How we keep LightDrawer trustworthy

LightDrawer is not SOC 2 or otherwise certified. This page lists the controls that are actually in place, so you can check them yourself.

## What you can check

- **Your file stays on your computer.** The site hashes the file in the browser and does not upload it. [How it works](../README.md#how-it-works).
- **The code is public.** LightDrawer is open source under the [MIT license](../LICENSE). Proposed changes go through a pull request. [CONTRIBUTING.md](../CONTRIBUTING.md).
- **You can report a security problem in private.** [SECURITY.md](../SECURITY.md) tells you how. Write to security@lightdrawer.org, or open a [private GitHub advisory](https://github.com/desynced/lightdrawer/security/advisories/new). There is no bounty.
- **The site publishes a security contact.** [/.well-known/security.txt](https://lightdrawer.org/.well-known/security.txt) points at those same private advisories. The copy in this repo is [web/ui/.well-known/security.txt](../web/ui/.well-known/security.txt).
- **Tests run on every change.** GitHub Actions runs the offline test suite on every pull request and every push to main. [ci.yml](../.github/workflows/ci.yml).
- **Dependencies get update requests.** Dependabot opens weekly pull requests for npm packages and for GitHub Actions. [dependabot.yml](../.github/dependabot.yml).
- **The automation is pinned.** Every Action in the workflows is pinned to a full commit SHA, with the version written next to it. A moved tag cannot swap in different code. [.github/workflows](../.github/workflows).
- **An outside score is published.** [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/desynced/lightdrawer/badge)](https://scorecard.dev/viewer/?uri=github.com/desynced/lightdrawer) [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/desynced/lightdrawer) checks this repository. The badge updates after the [Scorecard workflow](../.github/workflows/scorecard.yml) has published a result.
- OpenSSF Best Practices badge (passing, self-certified): https://www.bestpractices.dev/projects/16664
- **Release files can be checked.** When a version tag is pushed, the [release workflow](../.github/workflows/release.yml) builds the files and GitHub signs a provenance statement for them. [Verifying releases](../README.md#verifying-releases) is the short version of how to check.
- **Changes are written down.** The [changelog](../CHANGELOG.md) lists what changed in the software. Its **Operations** section lists changes to how the live site is run, which are not code.
- **A receipt does not require trusting us.** Three public witnesses record the fingerprint: [OpenTimestamps](https://opentimestamps.org) (Bitcoin), an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp authority (FreeTSA), and public [Certificate Transparency](https://certificate.transparency.dev) logs. Each receipt includes an offline checker, `verify.html`, so the check still works if this website is gone. [Verify without LightDrawer](../README.md#verify-without-lightdrawer).

## Technical detail

Hashing uses SHA-256 in the browser, in 4 MB chunks, so the file bytes are not sent to the Worker. What is stored, and for how long, is described in [HOW-IT-WORKS.md](../HOW-IT-WORKS.md).

The CI workflow checks out the repo with credentials persistence turned off, installs from `package-lock.json` with `npm ci`, and runs `npm test` (`node scripts/build.mjs && node test/run.mjs`) on Node 20. It then runs `npm run lint` (ESLint on `src/`, `scripts/`, and `test/`). It does not run `test/e2e_browser.py` or `npm run test:live`.

Dependabot groups minor and patch updates for npm and for GitHub Actions, and keeps at most five open update pull requests for each. The workflow files pin `actions/checkout`, `actions/setup-node`, `actions/upload-artifact`, `actions/attest-build-provenance`, `ossf/scorecard-action`, and `github/codeql-action/upload-sarif` to a 40-character commit SHA. The SLSA generator is the exception: `generator_generic_slsa3.yml` is called at tag `v2.1.0` (commit `f7dd8c54c2067bafc12ca7a55595d5ee9b75204a`). A commit SHA is rejected by that generator and is not a ref `slsa-verifier` trusts.

Scorecard runs on a push to `main`, every Saturday, and on the `branch_protection_rule` event. The job publishes results (`publish_results: true`) and uploads the SARIF file to code scanning. The workflow's own permissions are read-only except for `security-events: write` and `id-token: write` on that job.

The release workflow runs only when a tag matching `v*` is pushed. After the same offline tests, it builds `lightdrawer-<tag>.tar.gz` containing `public/`, `build/core.js`, `src/`, `migrations/`, `schema/`, `trust/`, `package.json`, `package-lock.json`, `wrangler.jsonc` (the committed template, placeholders only), `LICENSE`, `README.md`, and `CHANGELOG.md`. It also runs `npm pack`, which writes `lightdrawer-receipts-<version>.tgz`. `SHA256SUMS.txt` covers that archive, the npm pack tarball, and a standalone `verify.html`. It does not cover the provenance files. `actions/attest-build-provenance` signs those files with GitHub's keyless OpenID Connect certificate (Sigstore). They are attached to the GitHub Release for that tag, and so is one `*.intoto.jsonl` bundle per signed file, copied from that same attestation. A separate job then calls the SLSA GitHub generator (`generator_generic_slsa3.yml` at `v2.1.0`) with the base64 `sha256sum` lines for those files. The generator signs SLSA Build Level 3 provenance and attaches `lightdrawer-<tag>.intoto.jsonl` to the same release. The notes are the matching changelog section when one exists. Check the native attestation with:

```sh
sha256sum -c SHA256SUMS.txt
gh attestation verify lightdrawer-vX.Y.Z.tar.gz \
  --repo desynced/lightdrawer \
  --signer-workflow desynced/lightdrawer/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z
```

Replace `vX.Y.Z` with the tag you downloaded (in both places). A successful check shows the file was built by this repository's release workflow from that tag. This is the usual check, and it is what already works for `v1.6.2`.

You can check `verify.html` and `SHA256SUMS.txt` the same way.

Starting with the first release after this change, you can also check a downloaded bundle offline:

```sh
gh attestation verify lightdrawer-vX.Y.Z.tar.gz \
  --repo desynced/lightdrawer \
  --bundle lightdrawer-vX.Y.Z.tar.gz.intoto.jsonl \
  --signer-workflow desynced/lightdrawer/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z
```

`verify.html` and `SHA256SUMS.txt` take the same `--bundle` flag with their own `.intoto.jsonl` file. The npm pack tarball does too, from the first release that ships it.

Starting with the first release after the SLSA generator was added, check `lightdrawer-vX.Y.Z.intoto.jsonl` with `slsa-verifier`:

```sh
slsa-verifier verify-artifact lightdrawer-vX.Y.Z.tar.gz \
  --provenance-path lightdrawer-vX.Y.Z.intoto.jsonl \
  --source-uri github.com/desynced/lightdrawer \
  --source-tag vX.Y.Z
```

The same file covers `verify.html`, `SHA256SUMS.txt`, and the npm pack tarball. [Verifying a release](../SECURITY.md#verifying-a-release) has both commands.

`v1.6.2` is the first release with signed build provenance. That provenance is in GitHub's attestation store. The `v1.6.2` release does not include an `*.intoto.jsonl` file. `v1.6.3` includes the native attestation bundles as `*.intoto.jsonl` files and does not include `lightdrawer-v1.6.3.intoto.jsonl` from the SLSA generator. Tags `v1.0.0` through `v1.4.0` were pushed before the release workflow existed, so they do not have it. Versions 1.5.0 through 1.6.1 were never tagged; their changes are included in `v1.6.2`.

The offline checker is built into `public/verify.html` from `web/ui/verify.html`. It can check a receipt from a local file. It does not need this website unless you opt in to an online upgrade.

## Repository settings

These settings live in GitHub, not in this repository's files. As of November 13, 2026 they are set like this:

- **Dependabot alerts and Dependabot security updates are on.** GitHub warns about known vulnerable dependencies and opens pull requests to fix them. Malware alerts for dependencies are on too.
- **Secret scanning with push protection is on.** GitHub scans the repository for leaked credentials and blocks pushes that contain a recognized secret.
- **Private vulnerability reporting is on.** Anyone can report a security problem privately through a [GitHub security advisory](https://github.com/desynced/lightdrawer/security/advisories/new).
- **`main` is protected by a ruleset.** The ruleset is active and nobody can bypass it. Every change to `main` has to go through a pull request, and the automated tests (the "Test" check) must pass before it can be merged. Force-pushes to `main` are blocked, and `main` cannot be deleted.
- **CodeQL code scanning is on.** GitHub's default setup runs CodeQL analysis on every push and pull request to `main`, and on a weekly schedule. Scorecard results are still uploaded to code scanning.

Not on:

- **Approving reviews are not required.** A pull request needs zero approvals before it can be merged. This is a one-person project.

If a setting here changes, this page should change with it.
