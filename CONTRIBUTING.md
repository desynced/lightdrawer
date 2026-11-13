# Contributing

LightDrawer is a public repository. The usual way to propose a change is a pull request against `main`.

Fork the repository (or use a branch), make the change, and open a pull request. Do not push straight to `main`. The ruleset requires a pull request, and the "Test" check must pass.

Run `npm ci && npm test` locally before you open the pull request. The same command runs in GitHub Actions.

When you add major new functionality, add or update tests for it in the automated suite.

Match the existing code style (quotes, spacing, comment tone). Do not reformat files you did not need to change.

Do not add secrets, tokens, private hostnames, or production Cloudflare IDs.

Do not change receipt or stamp formats unless the change is the point of the pull request and is written up in CHANGELOG.md and HOW-IT-WORKS.md.

Security problems should be reported privately, following [SECURITY.md](SECURITY.md), not in a public issue.

Questions and ordinary bugs can go in [GitHub issues](https://github.com/desynced/lightdrawer/issues).
