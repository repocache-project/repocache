# v0.6.0 combined native package installation rehearsal (issue #27)

## Objective

Before any real-host installation, verify that three independently developed
pieces compose and function on the **same actual disposable Debian 13 and
AlmaLinux 10 filesystem**:

1. Genuine fixed root-owned protected state namespace and lock creation
   via issue #31 (merged PR #267); no preexisting NGINX/REPOCACHE footprint.
2. Real locked generation-zero read and read-only conservative NGINX ownership
   check, without interpreting a successful prepackage observation as install
   approval.
3. The durable native package-effects marker from issue #27 (merged PR #268),
   **holding the same state lock throughout actual native APT/DNF signed-repo
   refresh, package installation, package inventory, NGINX syntax validation
   and vendor-unit provenance**. The test independently attempts another
   exclusive lock using a second descriptor before every native subprocess.
   It must be refused. After the transaction, the journal remains durable
   and repeated fresh installation is blocked pending explicit reconciliation.

The existing source-isolated official Debian APT and AlmaLinux DNF4 package
profile, native keyring and package verification, and real NGINX syntax
rehearsal are reused, not duplicated or replaced with synthetic executables.

## Execution and boundaries

The GitHub Actions matrix runs in new disposable Docker images with the
source checkout mounted **read-only**. The test requires an explicit CI-only
marker, Docker identity, root in the disposable image, supported OS and system
Python identity, a non-systemd PID 1 and no previously installed NGINX or
REPOCACHE state. The marker and environment are not cryptographic root
namespace evidence: **never invoke this code on a host or production VM**.

The test intentionally runs real APT/DNF and writes only inside the ephemeral
container. It does not provide a production entry point, authenticate the
operator, lock the actual host mount namespace, validate booted systemd/SELinux,
install the management CLI, provision TLS, start NGINX under systemd, activate
any repository route or recover native package effects. Repeated installation
is REFUSED until independently audited recovery is implemented. The report
always sets \`authorizes_host_installation: false\`.

This is useful Stage-A actual integration evidence for #25/#27/#31. It does
**not** satisfy either parent issue's native booted systemd/SELinux, signed
release or operational cache acceptance, does not waive #64's independent
security review, and is not a **GO to install the v0.6.0 server in a VM**.

On GitHub, review the two matrix jobs in
\`.github/workflows/server-v06-journaled-native-package.yml\` and the exact
HEAD run, not a local summary. Both must PASS and all mandatory checks must
also pass. Failed native repository signatures must remain FAIL/NOT VERIFIED;
do not override package-manager trust policy to make CI green.

Regressions: \`python3 -m pytest -q tests/test_ci_v06_journaled_native_server_install.py\`.
