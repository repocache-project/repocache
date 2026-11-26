# Client privileged source-helper contract (design only)

**Status:** Maintainer-approved minimal helper trust boundary (2026-11-09); no installed privileged writer; [issue #24](https://github.com/repocache-project/repocache/issues/24).  
**Scope:** Debian 13 and AlmaLinux 10 only.  
**Related:** protected staging #131, sandbox atomic recovery #132, source preflight #133, metadata #134, metadata-transaction integration #135. #131–#135 are merged into main. This document proposes a future helper only and does not grant production write authority.

## Security model

The interactive or scriptable `repocache-client` is unprivileged by default. A future *minimal, root-owned helper* should be invoked only through a narrow non-interactive command with explicit arguments, and only from a trusted installed binary/package. The helper, not the CLI, is the ultimate authority for a change. It must not accept an arbitrary file path, shell command, remote catalog payload, unchecked repository URI, user-supplied temporary-file path or unsigned write recipe.

**Proposed fixed operations** (not currently available):

| Operation | Authority and expected behavior |
| --- | --- |
| `status` | Read-only status; redact credentials and secret metadata |
| `validate` | Read protected owned manifest + exact transaction; check local sources, grammar, upstream fallback and signature/TLS policy without writing |
| `commit` | After validation, mutate only allowlisted, manifest-owned repository entries under a global transaction lock; use a validated, prepared and integrity-protected plan identifier, not arbitrary file bytes |
| `recover` | Inspect a journal after interruption, restore only when the current inode/digest/attrs provably belong to this transaction, otherwise refuse and retain evidence |
| `restore` | Administrator-authorized reversion, with the same validation gates, not a filesystem-wide force overwrite |

This table is a proposed logical interface, **not approved CLI syntax**; integrate with CLI v1 and UC-22/27 before implementing any executable contract.

## Trust boundaries and authorization

- Root-only mutation and private state owner; no implicit sudo/polkit escalation from script-friendly client commands. Do not create a network-facing daemon or delegate through NGINX.
- Use `openat2` resolution restrictions (or a thoroughly audited, equivalent dirfd strategy), strict allowlisted source directories, inode/type/owner/link/permission checks, anti-symlink/hardlink protections and bounded payload sizes.
- Manage stable ownership IDs independently of discovery hashes. Reject unknown or externally modified repositories. Confirm the exact original source content and all security metadata immediately before committing.
- Coordinate APT/DNF native locks and a REPOCACHE exclusive transaction lock. Fail fast with a script-stable nonzero exit code while package managers are active; do not block waiting or rewrite under package-manager activity.
- Store original and prior approved configuration, signatures, ownership and validated transactional states privately with strict retention and recovery policy. Never log or expose credentials, xattr values, tokens, private keys, or full original source bytes.
- Preserve original package verification (APT InRelease/Release GPG, DNF repo metadata and package policy), scoped TLS CA and native fallback; the helper must refuse changes if fallback and trust cannot be proven for the concrete repository.
- Treat `security.selinux` and unknown xattrs as a blocker until verified on a **booted AlmaLinux 10 enforcing environment**. Standard GitHub Actions containers do not provide this acceptance evidence. The CI enforcing test is deferred, the production security requirement is NOT WAIVED.
- For privileged commits, refuse disk/IO/memory exhaustion and uncertain recovery conditions without silently deleting snapshots. A clean rollback route and administrator-visible diagnostic state are mandatory.

## Recovery-specific invariants

Each intent must record the original and intended source (device, inode), content digest and normalized security metadata. The new temporary file must be fsynced before the journal intent is durable. On restart:

1. Observe exact source inode + bytes + metadata under trusted dirfds and the exclusive transaction lock.
2. If the original is still present, cancel an interrupted install only if the pending temp is demonstrably the journalled inode. Unknown temp => conflict, no deletion.
3. If the intended update is present, finish a safe rollback only when no external edit occurred; otherwise preserve it and report a conflict.
4. For interrupted rollback with the original bytes still staged as a journalled temporary file, verify temp inode/content/ACL/xattrs before resuming the pending replacement. Missing, symlinked or altered temp => conflict.
5. Never infer permission to overwrite from a matching SHA-256 alone, and never automatically remove unmatched temporary files.

The current sandbox laboratory tests some of these invariants under synthetic conditions. It does not guarantee Linux rename compare-and-swap semantics against a concurrent actor of equal privilege; **there is no general atomic CAS rename provided by `os.replace`**, and a precommit `stat` is not sufficient for a production race-proof writer.

## Acceptance evidence required before helper installation

The helper is **NOT IMPLEMENTED** and source edits remain blocked until all relevant evidence is PASS: protected ownership registry; real APT/DNF parser and multi-entry preservation; authentic package manager fallback and TLS/GPG tests under failure; root/non-root permission paths; fail-fast locks; race testing under hostile concurrent processes; complete fault injection including SIGKILL, disk-full and power failure; SELinux enforcing, ACLs and xattrs; signed clean-install/upgrade/recovery workflow; compatibility and migration; reviewed CI and security gates; explicit maintainer merge approval.

No production use and no `repos sync --apply` enablement follow from this design alone.


## Approved helper architecture and UC-45 decision (2026-11-09)

The maintainer approved a narrowly-scoped, root-owned helper for fixed
status, validation, commit, restore and recovery responsibilities, with
least privilege and explicit OS authorization. This approval is **not** an
authorization for an installed writer or real package-manager source changes.

UC-45 requires an **explicit new administrator approval for each new exact
server-published cache route**. A changed host, port or path is not covered
by an old authorization, even if the upstream and repository ID remain
unchanged. The client must compare an independently authenticated active
catalog with an owned source baseline, verify TLS, signature trust and
native upstream fallback, and obtain fresh route-specific approval before
any later privileged source transaction.

The existing root-only sandbox approval record now binds one exact validated
HTTPS destination through SHA-256 (schema v2). A different proposed route
is rejected before transaction staging. This lab authorization is immutable
per candidate and cannot be silently reused or replaced. The production
route reapproval protocol, helper installation, privilege handoff and actual
native source writer are NOT IMPLEMENTED / NOT VERIFIED. Installed
repocache-client repos sync --apply remains disabled.

## Safe incremental fixed-operation helper implementation

The existing non-installed read-only source_helper_preview module now
supports a fixed verify-route-approval operation for the private,
root-owned candidate and route approval sandbox registry. It accepts only
a strict candidate identifier and SHA-256 digest of an exact approved
HTTPS route; no raw route, arbitrary path or shell command is accepted.
It verifies root authorization, protected approval and candidate identity,
and the whole source baseline without disclosing route or source bytes.

Native production invocation is refused (NOT_INSTALLED). Non-root fixture
invocation is rejected before reading any protected approval (ROOT_REQUIRED).
Unknown, mismatched, tampered or stale approvals are refused, without any
source mutation. The module is NOT installed as a privileged helper.
The installed client still refuses repos sync --apply and no commit,
restore or recovery operation is exposed.

## Non-installed conservative structural validation

The fixed validate-source operation inspects allowlisted APT .list, deb822
.sources and DNF .repo source files, read-only, using the existing pinned
directory-FD source preflight and original-file inode/metadata/digest checks.
It enforces a conservative entry grammar for all discovered entries and
refuses unsupported, empty, ambiguous or unsigned forms as a whole.
Local mirrorlist and DNF metalink/mirrorlist syntax is not certified.
Outputs contain only the format and bounded entry count, no paths or bytes.
The native action requires root and never elevates privileges automatically.

A structural subset PASS is not native APT/DNF acceptance, package signing
or fallback validation, ownership authority or real source-write permission.
No privileged helper is installed and repos sync --apply remains disabled.
Systemd and enforcing SELinux host tests remain reserved for final v0.6.0
native validation as requested by the maintainer.


## Fail-before-I/O disabled apply boundary (v0.6 Stage A)

Until an authenticated, installed, root-owned client writer is independently
reviewed, `repocache-client repos sync --apply` is always rejected **before**
local source discovery, OS inspection, installed-server configuration loading,
catalog retrieval, network access or changes. The refusal preserves the
existing CLI error code and JSON contract and does **not** imply that
`--apply` is implemented. An unprivileged consent flag never grants root
authority; the complete original #24 installed-native acceptance remains open.


## Root-bound current catalog check

The source-only root validator now independently fetches the current
catalog from the protected installed HTTPS origin, with fixed native
system CA trust and exact UC-45 upstream/cache equality. It rejects
legacy or changed routes and rechecks local approval/origin/source under
the client transaction lock. This is a non-activating validation step:
it neither issues administrative consent nor establishes live server
activation, native fallback, source ownership or transaction authority.
The protected approval issuance and native writer remain outstanding.


The internal, uninstalled issuance primitive additionally requires an
explicit exact-route digest and protected schema-2 pending proposal
binding source inode and metadata. It publishes immutable consent with
atomic no-replace semantics and durable directory fsync. It has no
installed CLI entry point; trusted pending proposal preparation,
labelled-state handling, native commit/recovery and full acceptance
remain open. Legacy schema-1 lab approvals cannot satisfy native
validation.


A root-only internal preparer now builds that pending proposal from an
exact file/entry digest selection resolved independently in fixed native
source directories. It validates the exact active mapping, source
identity and compiler result without accepting caller-supplied URLs or
paths. Preparation and explicit approval are separate state transitions;
no public command or installed writer is enabled. A route change
requires new consent; previous records are not overwritten.


## Authenticated client helper candidate

The independent trusted-checkout staging tool
`scripts/stage_native_client_helper.py` authenticates the v0.6 archive
through the existing Ed25519 verifier and closed source extractor,
including exact commit/archive pins and dependency policy. It builds
a deterministic isolated OS-Python executable with only the fixed
client validation modules, no server authority or sandbox writer.
The stage is private, no-replace and includes a content receipt;
there is no unsigned path or install/activation operation. Tests
exercise disposable signatures, bad signatures/pins, closed module
inventory and ambient import isolation. The trusted-checkout tool
still requires release-inventory reconciliation before publication.
Installed native helper placement and source mutation remain disabled.


The booted guest now exercises actual fixed root-only placement of this
non-activating executable, using a freshly generated disposable Ed25519
identity and the unchanged verifier with a private fixture trust directory.
Bad signature must precede placement; identical retry must preserve inode,
bytes and timestamps; the executable must deny non-root execution.
This placement entry is VM-guarded and not in the production installer.
It is not installation or acceptance of the real source writer.


The authenticated VM placement additionally provisions the fixed
`/var/lib/repocache-client/approved-entries` registry and an empty,
root-owned 0600 transaction lock only after signature verification and
executable readback. Bootstrap uses nofollow dirfds, exact private modes,
policy-checked attributes, durable directory/lock creation and repeated
inode checks. It never replaces an existing lock or recreates a missing
lock beside transaction evidence. Retry is idempotent; unsafe existing
state is retained and refused. The test-only installer still grants no
production write authority. Native application, consent handoff and
release installation remain separate gates.


The v0.6-only closed release source inventory now includes the trusted
client staging tool in both the builder and verifier. Historical release
inventories remain unchanged. This includes a non-activating tool, not
an installed source writer or a production activation permission.

## Approved isolated APT retained-companion recovery (2026-11-25)

The maintainer explicitly approved implementation, review and validation
in isolated environments only. New APT test transactions use journal
schemas 4/5 (metadata-free / metadata-bearing), bound to the original
approval, compiler bytes and exact inode identities. Before restoring a
source which may have been read by APT, fsync the upstream-only companion
candidate and durably journal its inode; atomically replace the known
cache-bearing companion, verify bytes and ownership, then restore the
source. Interrupted companion-only publication is conservatively retained;
an intent which never published a companion may clean its known staged
inode. Recovery never needs the catalog or issues new consent. The
retained file stays root:root 0644 without unexpected metadata. Restored
IDs cannot be reused; missing/foreign inode or contents fail closed. No
automatic retained-file deletion. Legacy lab schemas keep their explicitly
separate old test behavior, not a production migration mechanism.

An orphan staged before its intent is durable requires manual inspection;
no unknown temp deletion or claim of atomic CAS against UID 0. This does
not revoke a mirror list already fetched by APT, prove quiescence, define
production retention garbage collection or enable installed writes. Real
SIGKILL at each new durable boundary and actual booted catalog-bound
recovery are required; exact-HEAD acceptance remains NOT VERIFIED until
executed. The public CLI and installed helper remain non-activating.

### Actual journal recovery with a stale native APT reader

The guarded Debian VM additionally exercises the real retained-companion
transaction and actual APT parser in the same scenario. A fresh private
mount namespace exposes the marked fixture's APT directory and native
lock inodes only to the traced child. The parent remains in its original
namespace, recovers the actual SIGKILL journal while the reader is paused
before taking the lists lock, and then resumes APT. The fixture requires
signed HTTPS metadata from the original upstream, no cache requests, no
unsandboxed download, preserved journal/companion identity, and unchanged
host sources. This is not an installed writer, production mount strategy,
quiescence guarantee, or evidence of revocation of previously fetched data.

The native stale-reader journal proof also exercises a real deb822
`.sources` stanza (not just a one-line `.list`). The same authenticated
catalog preparation/approval, exact native lists-lock syscall barrier,
SIGKILL and retained-companion recovery run in a separate marked fixture.
The formerly selected cache is made healthy again after recovery and before
resuming the previously parsed deb822 reader. The exact approved route serves
a copy of the signed repository; an authenticated HTTPS positive control
requires status 200 and byte-identical InRelease and all three package index
representations. Only those explicit control requests are cleared from the
observed request log while the native reader remains stopped at the syscall
barrier. After resume its metadata must still come exclusively from the
signed upstream, with zero native-reader cache HTTP requests and no
unsandboxed APT download. Optimized Python execution is refused before the
native fixture begins. The exact original stanza, ownership/mode and
retained companion inode are checked after repeated recovery. This tests
an earlier reader that has not yet fetched the companion; it does not prove
revocation of already-fetched URLs or authorize an installed source writer.


### Incomplete journal publication

A failed journal write/fsync can leave the exact private
`.pair-<id>.pending` leaf alongside an older committed journal or before
the first journal exists. Under the existing exclusive state lock, every
sandbox apply/restore/recover entry now refuses this uncertain state before
reading the old journal or touching any source, mirror or staging file.
Any kind of pending leaf (including a dangling symlink) is refused without
following it; lookup errors are not treated as absence. The file and all
known and unknown inodes remain available for manual inspection. Do not
automatically promote, delete or overwrite incomplete journal evidence.

The disposable APT retained-companion and DNF pair tests inject ENOSPC at
the actual pending-file fsync for each apply and restore publication stage.
They require the previous journal phase (or absence), pending evidence and
every fixture file's bytes, inode and metadata to remain unchanged across
subsequent refusal of all three operations. The injection is a simulated I/O
failure, not a full-filesystem or power-loss test. There is no new installed
writer, automatic orphan cleanup, CLI contract or production permission.
