# Changelog

## v0.5.0 (candidate preparation — not published)

Prepare the reviewed source and schema-1 offline-wheelhouse metadata for the
next owner-signed candidate. The release policy explicitly permits upgrades
from the immutable public v0.4.0 while retaining the Debian 13 / AlmaLinux 10
targets, the frozen source-TAR inventory accepted by the v0.4.0 updater, and
the separately authenticated first-party application wheel.

This entry is **not** release acceptance. A real owner-approved unsigned build,
independent Node24 artifact readback, offline owner-key signature, exact signed
Draft acceptance, public-v0.4.0-to-v0.5.0 native upgrade/repair/rollback, and
separately authorized publication remain subject to issue #76 and the
applicable #88 operator criteria. No server endpoint activation is implied.

## v0.4.0 (published 2026-10-21)

First planned public REPOCACHE release, based on a selectively sanitized source snapshot, with a new Git history. **The v0.4.0 production product is a frontend CLI/TUI for an existing, operator-configured NGINX repository cache; NGINX provisioning and automatic client-source configuration are outside this release.** The immutable public v0.4.0 release and its postpublication acceptance are recorded under issue #71. This is the first standalone public release: migration from pre-public installations (including v0.3.0) is **not supported**. The public v0.4.0 release policy has no previous-version compatibility allowlist; the historical migration prototype is not shipped in release archives.

Planned work includes Debian 13/AlmaLinux 10 native Python support, non-interactive update discovery and selection, Ed25519 authenticated releases, hash-pinned offline dependencies, rootless updater hardening and durable recovery. Implemented code is not the same as verified release behavior; consult CI and PR acceptance evidence.

**Security hardening (#35):** Explicit same-version update no longer returns `already-installed` based on a matching service-owned manifest or existing executable. Publisher identity is checked again and authenticated offline assets are installed into a new generation. Refuse symlink, hardlink, incorrect owner and unsafe mode drift on active/staged runtime paths and protected launcher ancestors. This approach does not attest an existing environment against a compromised service UID; recovery must not execute a suspect installed CLI.

Earlier private-development versions are **not republished** or automatically licensed by the new public repository.
