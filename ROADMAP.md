# Roadmap

This is what LightDrawer intends to work on over roughly the next year, and what it does not intend to do. These are intentions, not promises. Plans can change, and items may land in a different order or not at all. Changes that ship are recorded in [CHANGELOG.md](CHANGELOG.md).

## What we intend to work on

- **More plain-language guides.** Add example pages for other situations, in the same style as the guides under [/examples/](https://lightdrawer.org/examples/), and keep the existing ones accurate.
- **Server-to-server stamps.** Keep stamp keys for trusted callers working as documented in the README, and make issuing, rotating, and revoking them simpler.
- **More reliable OpenTimestamps upgrades.** Make it smoother to turn a pending Bitcoin proof into a finished one later, from the site and from the offline checker `verify.html`.
- **Reproducible release files.** Make the release tarball byte-for-byte repeatable from the tagged source, so anyone can rebuild it and compare checksums. The built site files are already repeatable.
- **More tests.** Raise branch coverage of the automated test suite, especially for the certificate-log code and the stamp-key script, and keep adding a regression test for each fixed bug.
- **Accessibility.** Review the site and the offline checker for keyboard use, screen readers, and contrast, and fix what is found.
- **Keep the witnesses current.** Recheck the Sigstore Rekor integration as Sigstore moves to Rekor v2, and refresh the bundled certificate-log key list when logs change.
- **Keep the security work going.** Keep dependencies updated, workflows pinned, and the [assurance case](docs/ASSURANCE.md) in step with the code.

## What we do not intend to do

- Upload, host, or store people's files. Only a fingerprint leaves the device.
- Require accounts or sign-in to make or check a receipt.
- Make a receipt depend on trusting LightDrawer. Receipts must stay checkable with public tools and the offline checker, even if this website is gone.
- Treat the certificate-log stamp as a replacement for the Bitcoin proof. It stays an extra witness.
- Claim legal compliance or certification. LightDrawer is a tool. It does not certify anything.
- Fold LightDrawer into another product. It stays a standalone project.
