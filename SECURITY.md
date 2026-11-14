# Security policy

## Reporting a vulnerability

Email [security@lightdrawer.org](mailto:security@lightdrawer.org).

You can also open a private GitHub advisory:

https://github.com/desynced/lightdrawer/security/advisories/new

The site file `/.well-known/security.txt` also points to GitHub private advisories.

Please say what you found, how to reproduce it, and what you think the effect is. We will try to respond.

There is **no bounty**.

## What happens next

We will acknowledge a report within 14 days.

We will aim to fix a confirmed vulnerability within 60 days, sooner when it is severe.

If a CVE (or similar) is assigned before a fix is released, the changelog entry for that release will name it.

There is still no bounty.

## In scope

- The LightDrawer website
- The Worker
- Receipts
- Related code in this repository

## Out of scope

- Third-party witnesses: OpenTimestamps calendars, FreeTSA, and certificate logs. Report those to the projects that run them.
- The separate [lightdrawer-mcp](https://github.com/desynced/lightdrawer-mcp) repository. It has its own `SECURITY.md`.

## Verifying a release

A `v*` tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml). That workflow builds the release files and attaches them to the GitHub Release for the tag, including `lightdrawer-vX.Y.Z.intoto.jsonl`. That file is SLSA Build Level 3 provenance from the SLSA GitHub generator. The same workflow also signs a native GitHub attestation for those files.

Download `lightdrawer-vX.Y.Z.tar.gz` and `lightdrawer-vX.Y.Z.intoto.jsonl` into one folder. Replace `vX.Y.Z` with the tag (in the filenames and in `--source-tag`).

Check the SLSA provenance:

```sh
slsa-verifier verify-artifact lightdrawer-vX.Y.Z.tar.gz \
  --provenance-path lightdrawer-vX.Y.Z.intoto.jsonl \
  --source-uri github.com/desynced/lightdrawer \
  --source-tag vX.Y.Z
```

`slsa-verifier` is the binary from [slsa-framework/slsa-verifier](https://github.com/slsa-framework/slsa-verifier/releases). The same provenance file also covers `verify.html`, `SHA256SUMS.txt`, and the npm pack tarball. Pass that filename in place of the archive.

Check the native GitHub attestation:

```sh
gh attestation verify lightdrawer-vX.Y.Z.tar.gz \
  --repo desynced/lightdrawer \
  --signer-workflow desynced/lightdrawer/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z
```

`v1.6.3` has native attestations and per-file `*.intoto.jsonl` bundles from those attestations. It does not have `lightdrawer-v1.6.3.intoto.jsonl` from the SLSA generator. `v1.6.2` has a native attestation and no `*.intoto.jsonl` file. Tags `v1.0.0` through `v1.4.0` were pushed before the release workflow existed.
