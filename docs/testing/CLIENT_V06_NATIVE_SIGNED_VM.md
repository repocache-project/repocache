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
