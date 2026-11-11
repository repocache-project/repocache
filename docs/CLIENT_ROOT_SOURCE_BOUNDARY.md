# Root-owned source approval validation boundary — issue #24

**Status:** uninstalled source-only client helper, **not an APT/DNF writer**.
This code is not imported by the installed `repocache-client`, does not
modify `client/install.sh`, and does not change the command contract.
`repocache-client repos sync --apply` deliberately still refuses.

## Fixed trust boundary

`client/root_source_boundary.py` implements fixed **status** and
**validate --candidate ID** operations. The only accepted ID is 32 lowercase
hexadecimal characters; no network catalog, raw URL, filesystem path, shell
command, temporary-file path or signed/unsigned write recipe is accepted on
the command line. Only UID 0 may inspect the native boundary. No implicit
sudo, service, daemon, setuid bit, privileged package install or remote access
is provided.

For validation, the helper follows only fixed root-owned directory entries
under `/var/lib/repocache-client/approved-entries`, opened by anchored
`O_DIRECTORY|O_NOFOLLOW` file descriptors. It requires pre-provisioned
private `0700` state, existing `0600` root-owned and single-linked manifest
and exclusive flock inode, stable pathname/inode metadata, bounded manifest
bytes and no unknown xattrs. It never creates the state or a lock file. All
filesystem inspection is performed while holding the exclusive lock
nonblockingly; a competing client operation fails immediately.

The current strictly bounded schema-1 candidate manifest contains only:
`schema`, `id`, allowlisted `source`, `source_sha256`, `entry_sha256`,
`upstream`, exact `cache`, and `route_sha256`. Duplicate JSON fields,
unknown keys, unsigned metadata overrides and stale route/source evidence
are rejected. The exact cache route digest must match the recorded approved
route, and the original file baseline + unique selected entry must match the
compiler used to generate an APT/DNF fallback proposal. The manifest **is not
a route-approval issuance protocol**; there is no CLI to create it, and a
self-supplied/caller-controlled manifest is never enough to authorize writes.

For native files, the helper reuses a separate inode-pinned source preflight,
then independently reopens and hashes the allowlisted source beneath anchored
directory descriptors, compares the whole file and entry digest, runs the
non-activating fallback compiler, and verifies the same file again. It does
**not** treat a matching SHA-256 as a race-free compare-and-swap or evidence of
owner-consented source changes.

Status and validation responses never return the raw catalog, cache route,
source path, original file bytes, credentials, xattrs or private approvals.
All successful responses explicitly state:
`installed=false`, `write_eligible=false`,
`native_package_locks_verified=false`,
`package_signatures_verified=false`, and
`native_fallback_verified=false`. There is deliberately **no commit,
recover or restore entry point** yet.

## Native Stage-A CI

`tests/test_client_root_source_boundary.py` tests malformed/duplicate
manifests, root denial, fixed operation refusal, file mode/hardlinks/symlinks,
source drift, exact route mismatch, exclusive locking and nonmutation.
`scripts/smoke_client_root_source_boundary.py` runs actual UID-0 positive and
negative tests on ephemeral `/tmp` trees with strict double test markers,
while `.github/workflows/client-helper-preview.yml` exercises the native
OS Python on Debian 13 and AlmaLinux 10 disposable containers. The
container-only test root is never exposed as a command-line argument, cannot
be used on `/` without real UID 0 and is never a production source writer.

## Still mandatory before opt-in sync can be enabled

- Secure **administrator-issued** per exact route approval with authenticated
  origin/catalog (#28/#95), trust and source ownership; protected on-disk
  provenance, explicit consent, revocation, and idempotent reconciliation.
- Root-owned, deployed and package-authenticated helper lifecycle with a
  bounded OS authorization mechanism, race-proof native APT/DNF transaction
  exclusion and current package manager lock verification.
- Durable, per-file managed ownership manifest, two-version recoverable
  original/previous backup policy, journal and multi-resource APT mirror-file
  plus source-file atomic/recoverable implementation. Never rely on ordinary
  `os.replace` as a compare-and-swap against same-privilege writers.
- Strict on-disk key, CA and metadata trust, actual package-manager
  executable verification, failure-injection, rollback and repair.
- Final booted Debian 13 / AlmaLinux 10 SELinux-enforcing and owner signed
  artefact acceptance through issue #19 and release authority gates.

This PR is a non-activating **stage-A subcomponent**. It does not satisfy
original #24 repeated installed `--apply`, real source writes, rollback,
signed native fallback, or release native acceptance criteria.
