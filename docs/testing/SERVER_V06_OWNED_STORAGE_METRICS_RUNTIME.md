# Owned storage and metrics runtime rehearsal (#29)

Both supported x86_64 distro containers run the stock native NGINX master
and its packaged unprivileged worker against a **detached, private** root.
The actual cache/log and per-repository owner-marker bootstrap and private
metrics inode bootstrap are invoked, rather than manually creating the
cache or log files. The joined route and metrics renderer then produces
the fragments for two local TLS routes; the CI harness remaps only the
validated public upstream pins and fixed log path to its disposable local
TLS fixture. This is not an installed service or production configuration.

Each repository must return unchanged metadata and artifact bytes with observable
MISS/HIT, one origin request, real worker-owned cache files, a root-owned
0600 metrics inode and eight correctly parsed events (four hits and four
misses) through the CLI's metrics reader. The native stock logrotate
then performs two rotations, using the existing fixture marker
reconciliation and a test-only validated master reload. The old worker
generation must drain before requests resume; each subsequent fetch is
a HIT with the original bytes, private root-owned log mode, and unchanged
cache identities. The initial eight rows and two sets of four new rows
must be retained in the current file, `.1` and `.2.gz`. After stopping the process,
repeat preparation must preserve cached bytes/inodes, historical metrics
bytes, private inode and ownership marker. The test does not rotate a
live installed log, prove signed repository metadata, start systemd or
authenticate a host root. SELinux context policy and full installed
transaction/recovery remain separate #29/#31/#19 acceptance gates.

The workflow passes only the sixteen disposable privacy-limited log rows
as a short-lived CI artifact. A separate ordinary unprivileged CI job
runs the actual `repocache metrics show` JSON command on each exact
sample and checks observed counts and byte totals against the source
rows. It does not run the CLI with host-root privileges or transfer any
operator credentials, certificates, or production logs.

The rotation candidate has no service hook and must not be installed as a
standalone scheduled profile. This fixture uses an explicit validated reload of its own spawned master
and drains the old worker generation, not systemd or the host's NGINX. An
installed lock-coordinated strategy remains a separate acceptance gate;
no production reload authorization or label changes follow from this test.
An invalid private configuration is rejected by the syntax check before
any rotation or marker change; the running fixture and historical bytes
remain unchanged.

CI: `.github/workflows/server-v06-owned-storage-metrics-runtime.yml`.

## Booted VM extension (issue #29)

The integrated PR #237 smoke scenario now invokes a separately guarded native
guest wrapper, requiring exact QEMU/KVM, systemd PID1, x86_64, fixed disposable
hostname/source path, inactive packaged NGINX and the exact distro. Debian 13
reuses the existing detached root runtime (including actual worker MISS/HIT,
two rotations, marker reconciliation, metrics and repeat provisioning). The
guest installs stock logrotate only if missing, with the distro package manager.
The container command guard is unchanged.

AlmaLinux 10 exercises the **actual** security.selinux attribute on a detached
root while enforcing. Two calls to the existing fixture storage bootstrap
must refuse before any path, mode, owner, timestamp or label change. This is a
negative security test, NOT positive SELinux support. The implementation still
deliberately refuses unverified labels; an authenticated SELinux-aware
installed storage implementation and effective confined worker access are
required for the original #29 criterion. Never remove labels or disable
enforcement to make a fixture test green.

Inspect native-owned-storage-metrics.txt in each exact-HEAD smoke guest
artifact. The Debian experiment does not prove installed service rotation,
reboot persistence or actual signed-product repair; AlmaLinux negative
acceptance does not close the native functional gate.
