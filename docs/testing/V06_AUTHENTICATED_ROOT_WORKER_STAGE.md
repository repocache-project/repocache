# Authenticated v0.6 worker staging (#64)

Use the independently reviewed checkout for the verifier below. Supply a
private operator-owned staging parent, the exact source commit and the
independently reviewed archive SHA-256. The asset directory contains
the v0.6.0 source archive, its signed manifest and detached signature.

~~~sh
/usr/bin/python3 -IS scripts/stage_native_root_worker.py \
  --assets /absolute/incoming \
  --output /absolute/private-stage/worker \
  --commit "$REVIEWED_SOURCE_SHA" \
  --archive-sha256 "$REVIEWED_ARCHIVE_SHA256"
~~~

The verifier uses the existing independently provisioned host trust store.
It checks the detached signature, canonical v0.6 release identity, two
operator-supplied pins and signed compatibility policy before staging.
The source archive is extracted into a private temporary directory using the
closed v0.6 member inventory. The trusted builder packages source files as
data and does not execute code from the candidate.

The new private directory contains the deterministic executable, two unit
files and worker-receipt.json. Compare the receipt's identities and individual
file hashes with the planned authenticated native installation. The receipt
is a staging record and never substitutes for re-verification at the eventual
privileged installation boundary. An interrupted attempt without a receipt
requires a fresh output directory. This command does not install the worker,
change systemd/SELinux or activate NGINX.

The exact combined two-distro workflow tests this with disposable Ed25519
keys and the canonical verifier from #249. It covers matching artifacts,
wrong trust data, wrong owner pins, unsupported OS and existing output.
Real publisher signing and booted Debian 13 and enforcing AlmaLinux 10
acceptance remain separate gates.


After separately authorized placement, the trusted verifier can check
the actual files before starting the socket. Use the same assets and pins,
and replace the output option with --verify-installed. The readback checks
root-owned regular files at /usr/libexec/repocache/server-control-worker
and /etc/systemd/system/repocache-control.{service,socket}. It refuses
symlinks, hard links, unsafe ancestor ownership/mode, unexpected installed
permissions and any content difference. Actual unit loading, drop-ins,
SELinux labels and service behavior require separate native acceptance.


## Authorized file placement

The fixed installer accepts the same independently authenticated offline
assets and owner pins. Run from the trusted checkout as root on a supported
booted host. The command can prepare an absent fixed state namespace after
checking existing unit and worker destinations. The root-owned namespace
allows traversal to the public catalog directory (0711 parent, 0755 public).
The independent server state directory and its shared lock stay private
(0700 and 0600). The unprivileged application has a separate private home.
Existing namespaces must already match those modes. An interruption before
the complete protected lock exists requires operator reconciliation.

~~~sh
/usr/bin/python3 -IS scripts/install_native_root_worker.py \
  --assets /absolute/incoming \
  --commit "$REVIEWED_SOURCE_SHA" \
  --archive-sha256 "$REVIEWED_ARCHIVE_SHA256"
~~~

It reads PID 1's UnitPath, refuses conflicting units, unit overrides,
aliases, dependency links and an existing socket during incomplete work,
and places the executable and units at the fixed paths with root ownership.
A durable marker binds recovery to the same authenticated candidate.
Under that marker the placer creates missing fixed worker directories
below /usr and syncs the directory entries. It preserves existing safe
directory metadata. Re-executing with the same inputs resumes an interrupted
directory creation or no-replace placement. A completed placement is
checked without rewriting or creating directories.
An unrelated destination or a different candidate halts before replacement.

The placement command does not load, start or enable either unit. Review
the effective loaded unit and native labels and perform separately
authorized activation in the consolidated booted-host campaign.

## Stage a reviewed v2 proposal

Use a canonical v2 state snapshot and its independently reviewed SHA-256.
Run the same installer with the authenticated release asset arguments plus
`--stage-v2-proposal /absolute/reviewed-state.json --proposal-sha256 SHA256`.
It verifies the installed worker files and binds the snapshot to the actual
committed predecessor under the protected lock. A prior uncommitted proposal
is preserved. An exact staged retry is idempotent. A native package-effects
marker or pending WAL blocks staging and remains available for reconciliation.
Staging leaves the active state, NGINX and the catalogue untouched. Actual
activation still requires the separate kernel-credentialed worker operation.
