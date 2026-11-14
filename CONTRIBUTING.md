# Contributing

LightDrawer is a public repository. The usual way to propose a change is a pull request against `main`.

Fork the repository (or use a branch), make the change, and open a pull request. Do not push straight to `main`. The ruleset requires a pull request, and the "Test" check must pass.

Run `npm ci && npm test && npm run lint` locally before you open the pull request. The same command runs in GitHub Actions.

When you add major new functionality, add or update tests for it in the automated suite.

See [Coding style](#coding-style) below.

Do not add secrets, tokens, private hostnames, or production Cloudflare IDs.

Do not change receipt or stamp formats unless the change is the point of the pull request and is written up in CHANGELOG.md and HOW-IT-WORKS.md.

Security problems should be reported privately, following [SECURITY.md](SECURITY.md), not in a public issue.

Questions and ordinary bugs can go in [GitHub issues](https://github.com/desynced/lightdrawer/issues).

## Coding style

JavaScript follows ESLint's recommended rules (`@eslint/js` `recommended`) plus the settings in [eslint.config.js](eslint.config.js). `npm run lint` checks this, and CI runs it on every pull request. There is no separate code formatter. Match the existing code style (quotes, spacing, comment tone), and do not reformat files you did not need to change.

User-facing text (the site, the guides, the docs) is plain language. Say what LightDrawer does and does not prove. Do not claim certification, legal compliance, or guarantees.

## Code review

Every change, including the maintainer's own, goes to `main` through a pull request. The ruleset blocks direct pushes and force-pushes to `main`.

Before a pull request can be merged:

- The required "Test" check (`npm test` and `npm run lint`) must pass.
- CodeQL code scanning must not report a new alert. The ruleset itself requires only the "Test" check, so the maintainer checks CodeQL before merging. A real problem gets fixed. A false positive is explained in the pull request.
- The maintainer reviews it. Today LightDrawer has one maintainer (see [GOVERNANCE.md](GOVERNANCE.md)), so the review is the maintainer's. Changes made with automated tools or AI assistants are reviewed the same way.

What the reviewer checks:

- **Security.** Input from the browser or the network is validated. Nothing new is sent off the device beyond the fingerprint. No new host is called without an allowlist. Fail-closed behavior is kept. The [assurance case](docs/ASSURANCE.md) is updated if a defense or a trust boundary changes.
- **Tests.** New functionality has tests. A bug fix has a regression test where practical.
- **No secrets.** No keys, tokens, account or zone IDs, database IDs, private hostnames, or personal email addresses in code, docs, or commit metadata.
- **Formats.** Receipt and stamp formats change only when that is the point of the change, with CHANGELOG.md and HOW-IT-WORKS.md updated.
- **Docs and copy.** The changelog entry is accurate. User-facing text is plain language and makes no certification or compliance claims.

A pull request is acceptable when the checks pass, the reviewer has no open concerns, and the change fits the project's direction (see [ROADMAP.md](ROADMAP.md)).

Contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
