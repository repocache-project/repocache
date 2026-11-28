# Booted-native APT/DNF signed-metadata fallback acceptance (#24)

## What the existing v0.6.0 QEMU smoke now runs

The existing **smoke** jobs of
`.github/workflows/pr237-booted-native-vm.yml` exercise Debian **13**
and AlmaLinux **10 x86_64**, not Debian/Alma container substitutes.
Before running the native manager fixture, the guest verifies PID 1 is
systemd, QEMU/KVM virtualization, its disposable hostname and native
distribution. AlmaLinux must retain **SELinux Enforcing**.

The guest installs only the test tools it needs from the distribution's
existing package manager. A root-only, *VM-restricted* script reuses
`scripts/ci_client_native_fallback.py` unchanged to generate private
OpenPGP fixture keys, loopback HTTPS origins and isolated temporary
APT/DNF repository metadata. It invokes the real native package manager
against **private, temporary test configurations**. No system repository
configuration, installed package or production signing trust is changed.

| OS | Real package manager | Required observed checks |
| --- | --- | --- |
| Debian 13 | `apt-get` | Test-signed `InRelease`, real synthetic `.deb` download and exact SHA-256; preferred cache endpoint, HTTP 503 fallback, recovery, both unavailable, wrong TLS CA, modified `InRelease` and tampered `.deb` refusal |
| AlmaLinux 10 | `dnf5` | Test-signed `repomd.xml` verified against isolated guest-local OpenPGP key; preferred endpoint, fallback/recovery, both unavailable, wrong TLS CA and tampered metadata signature refusal; signed disposable RPM download, exact SHA-256 and native RPM signature verification in an isolated RPMDB, and corrupted RPM refusal |

The QEMU smoke already verifies client parser help and refusal of
`repos sync --apply` with no host source change. The extended client
guest additionally takes **before-and-after source byte/inode/mode/mtime
inventories and installed package inventories** for the root-only
native manager probe, and rejects any change. It never invokes a
REPOCACHE host source writer or installs the fixture packages.

## Evidence and limits

Run all applicable PR workflows and inspect the **exact HEAD** booted
QEMU jobs:

```sh
PYTHONPATH=src python3 -m pytest -q \
  tests/test_v06_vm_signed_client_guest.py \
  tests/test_ci_dnf_signed_rpm_fallback.py \
  tests/test_v06_vm_campaign_coverage.py
```

QEMU passes are narrow **Stage-B native-manager transport and package
trust checks**, not a demonstration of an actual installed REPOCACHE
NGINX caching service, a production signed repository or
`repocache-client repos sync --apply` changing system files. The
fallback test has two disposable loopback HTTPS origins and does not
constitute a real cache HIT. Do **not** mark the original full issue
#24 criterion for installed apply/rollback, protected host locks,
SELinux-labelled source changes or real client transparent upstream
fallback as PASS on this evidence alone.

Synthetic OpenPGP key material stays inside disposable guests. Genuine
publisher Ed25519 artifact acceptance and publication are separately
authorized Stage C (#76/#88). If a guest's signed metadata or
rejection/provenance checks fail, its QEMU job must fail rather than
claiming an accepted host.


The booted AlmaLinux RPM fixture uses the native RPMDB directory solely as
a SELinux label reference for the empty root-owned disposable RPMDB.
It verifies Enforcing and the exact rpm_var_lib_t label before running
rpm --initdb, with no host RPMDB fallback or policy relaxation. Container
tests do not relabel. This addresses the observed isolated .rpm.lock
permission error; successful execution on the new HEAD remains required.

The initial label-only retry still failed at RPMDB lock creation in `/tmp`.
The subsequent disposable VM probe allocates the database directly under
`/var/lib/repocache-ci-rpmdb-*`, verifies its native RPMDB label, and
removes it on exit. The fixture repository remains in `/tmp`. Initialization
failure reports bounded directory contexts without changing SELinux policy.
This correction requires fresh booted-native acceptance evidence.

## Actual read-only native client commands (#24)

The prior native CLI guard exercised help and disabled apply refusal, not
all three real read-only commands. The guarded booted guest now runs actual
non-root check, repos list and default repos sync against a disposable
loopback HTTPS catalog. Its test certificate is selected only in the
child's SSL_CERT_FILE environment; the host trust store is untouched.
A valid empty catalog requires successful TLS/catalog checks, unchanged
inventory, dry_run=true, planned_changes=0 and no write-eligible plan.
An unsupported catalog schema and foreign CA must refuse sync and report
the expected check status; list never contacts the server. No actual
repository origins are contacted. Snapshot the supported native source
files (including APT mirror companions when present) before the probe and
after every invocation, comparing exact file set, device/inode, owner,
mode, links, size, mtime, ctime and SHA-256. A wrong outcome, unexpected
stderr, malformed JSON or source drift fails the test. Native execution
remains NOT VERIFIED until the exact-HEAD booted Debian and AlmaLinux
campaign completes; no installed source writer, active catalog or real
publisher acceptance is claimed.

## DNF4 private lock directory continuity (#24)

The disposable DNF4 PID/RPMDB lock scope rewalks the fixed directories
from the private root without following symlinks, checks ownership and
permissions, and binds them to the retained directory descriptors before
publication, during revalidation and before claim cleanup. Unsafe parent
or leaf drift refuses further operations and retains the exact PID claim
for fixture review; the native test restores only its own disposable
permissions and removes its verified claim. The mechanism remains
fixture-only: it does not exclude earlier readers or authorize installed
source mutation.

The scope also pins each ancestor's device, inode, owner, group and mode
from the private root to both lock directories. A new safe-looking
ancestor cannot inherit the original scope by retaining the same lock
directory inode. The native fixture reparents its own RPMDB directory
while holding the lock, restores the original ancestor, and requires
the failed scope to retain its claim until explicit fixture cleanup.
This does not establish exclusion of already parsed DNF readers.

## Previously parsed DNF4 reader after route withdrawal (#24)

In the disposable enforcing guest, a third DNF4 library reader parses
the exact journal-published entry before SIGKILL recovery. Unlike the
existing whole-endpoint HTTP 503 and still-healthy former-cache cases,
the HTTPS origin stays healthy while the exact private route directory
is moved out of its document root and its catalog mapping is withdrawn.
A fresh verified TLS metadata request must return HTTP 404; the earlier
reader must request the withdrawn path but retrieve the exact RPM only
from upstream, with SHA-256 and native trusted RPM signature verification.
The fixture restores its own directory and catalog afterward; host source
and installed-package inventories must remain unchanged. This is evidence
of client fallback against a controlled route-level 404, not proof of
authenticated live REPOCACHE route revocation or installed source writes.
