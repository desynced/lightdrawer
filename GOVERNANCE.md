# Governance

LightDrawer is a small open source project with one maintainer. This page says who decides what, who does what, and what happens if the maintainer is unavailable. It describes how the project is actually run today. It does not describe a team that does not exist.

## Model

LightDrawer uses a single-maintainer model. The maintainer is **Joe Ball** ([@desynced](https://github.com/desynced) on GitHub). The maintainer makes the final decision on every change, release, and deployment of the hosted site at lightdrawer.org.

## Roles and responsibilities

**Maintainer: Joe Ball (@desynced).** Today this is the only person with write access to the repository.
- Reviews and merges pull requests into `main`.
- Tags releases. The release workflow builds and signs the release files.
- Runs the hosted site at lightdrawer.org.
- Answers security reports (see [SECURITY.md](SECURITY.md)) and code-of-conduct reports (see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- Keeps the documentation current with the code.
- Keeps the repository settings described in [docs/TRUST.md](docs/TRUST.md) in place.

**Contributors: anyone.**
- Open issues and pull requests, following [CONTRIBUTING.md](CONTRIBUTING.md).
- Contributors do not need write access. Every change, including the maintainer's own, reaches `main` through a pull request that passes the required checks.

**Security contact: security@lightdrawer.org.**
- This mailbox goes to the maintainer.
- It receives private vulnerability reports, as does GitHub private vulnerability reporting.
- It also receives code-of-conduct reports.

**Automation**
- Dependabot opens dependency update pull requests.
- GitHub Actions runs the tests, the Scorecard check, and the release workflow.
- Automated tools, including AI coding assistants used by the maintainer, have no authority of their own. The maintainer reviews their changes like any other pull request before merging.

## How decisions are made

1. A change is proposed as a GitHub issue or a pull request.
2. Discussion happens in the open on that issue or pull request. Security problems are the exception: they are handled privately as described in SECURITY.md.
3. The maintainer decides whether to merge, ask for changes, or close. When a proposal is declined, the maintainer says why.
4. Changes that affect what a receipt is, how it is checked, or how safe the service is are written up in [CHANGELOG.md](CHANGELOG.md). Changes to how the live site is run are listed under **Operations** in the changelog.

## Continuity

The maintainer has arranged sealed access-recovery instructions for a designated person. They cover GitHub, Cloudflare, the domain, and the security contact.

## Account security

The maintainer's GitHub account uses two-factor authentication with passkeys and an authenticator app, not SMS.

## Adding a co-maintainer

LightDrawer would welcome a second maintainer. A contributor who has made sustained, good-quality contributions over time can be invited by the maintainer. A new maintainer:

- is added to this page by a pull request, together with their role;
- gets write access only after that pull request is merged;
- must use two-factor authentication on their GitHub account.

If a second maintainer is added, this page will be updated to say how the two make decisions together and how reviews are shared.

## Changes to this document

Changes to governance go through a pull request like any other change.
