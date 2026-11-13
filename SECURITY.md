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
