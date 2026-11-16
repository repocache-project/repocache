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
