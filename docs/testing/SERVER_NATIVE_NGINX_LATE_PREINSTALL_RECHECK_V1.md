# Retained-lock NGINX conflict recheck immediately before APT/DNF (#27)

The early ownership scan rejects installed NGINX files and running NGINX
processes **before native metadata/network work**. Signed metadata refresh
and package installation are separate operations, however: an unrelated
NGINX process or new service unit can appear after the first preflight.
A stale positive preflight must not justify the later package mutation.

This Stage-A increment adds a **fresh**, bounded read-only check intended
to run immediately before each native APT/DNF metadata refresh or package
installation operation while the same durable #31 protected lock remains
contended. It reduces a demonstrable window of stale-snapshot risk; it
does **not** eliminate all process/service races and does not grant host
root authority, operator approval or permission to start a service.

## Function and locked transaction requirements

`recheck_fresh_native_nginx_before_manager` lives in the existing
`server_native_nginx_ownership_v1.py` first-party module. It is not an
installed host entrypoint or a new product CLI.

Its caller supplies the already-verified protected state-directory
descriptor. Before scanning, it:

1. Checks the state-directory inode/ownership/mode and the exact fixed
   `lock` inode (root-owned 0600, single link). A **different open file
   description** must fail to acquire the exclusive lock. This is a
   necessary contention observation, not proof of **who** holds it.
2. Requires an exact canonical, generation-zero, already-persisted native
   pending APT/DNF effects marker under that same state directory and
   refuses any simultaneous protected state transaction or torn marker.
3. Revalidates the exact pinned distribution and install policy, then
   scans every fixed NGINX file/unit marker and the live Linux
   `/proc/<pid>/comm` set. The protected state directory itself is the
   **one excluded NGINX marker**, because its ownership and journal have
   been verified separately. Existing NGINX, live NGINX process or any
   incomplete scan is a redacted, fail-closed refusal.
4. Reads the same protected journal again and rechecks separate lock
   contention before returning an **observation-only** result.
5. Always returns `authorizes_native_package_installation:false`,
   `authorizes_host_mutation:false` and `transaction_cannot_be_raced:false`.
   An earlier successful report cannot be cached as a future permission.

A live process can still start **after** the last scan. A trusted host
executor must independently authenticate root/OS/namespace, actual signed
APT/DNF input, operator authorization, service ownership and protected
state-v2 transaction and revalidate the boundary as late as possible.
Root ownership alone is not a verified signed installation identity.
Do not skip #64's required independent security review and approval.

## Real two-distribution CI behaviour

`.github/workflows/server-v06-native-nginx-late-recheck.yml` starts clean
disposable Docker userspaces for **Debian 13** and **AlmaLinux 10**, with
a read-only source checkout; it installs only test prerequisites in the
disposable image. The CI driver:

1. Refuses unsupported OS, architecture, host PID1/boot context, existing
   NGINX and protected state using the existing container guard.
2. Creates a real protected state directory and durable native package
   pending journal, holding the same exclusive Linux lock for all steps.
3. Starts a separate *Python* process that changes its kernel
   `/proc/<pid>/comm` to `nginx`. This represents a late process-name
   conflict **before native packages are installed**; it is deliberately
   **not** an actual NGINX daemon. While that process exists, attempts
   to invoke the native manager must be refused before the runner executes,
   without discarding the journal.
4. Stops the disposable process, rechecks a fresh empty process footprint,
   and performs the **actual** pinned-source APT/DNF metadata refresh and
   NGINX package installation. Each native operation rechecks the same
   pending journal and lock plus all fixed NGINX/process conflicts **right
   before calling the distribution binary**.
5. Confirms actual native NGINX package/syntax/vendor-unit checks pass,
   package-effects journal remains byte-identical and unreconciled after
   the operation, and retry remains blocked pending independent recovery.

No booted `systemd`, AlmaLinux SELinux enforcing, privileged installed
root worker, real host package installation, operator consent or service
reload is exercised. The driver never claims native host readiness.

Focused test invocation:

```sh
PYTHONPATH=src python3 -m pytest -q tests/test_server_native_nginx_preinstall_guard_v1.py
```

Unit regressions cover actual exclusive lock contention, missing/foreign/
corrupted journal, distro mismatch, late fixed-path foreign NGINX, late
running process, `/proc` denial, marker replacement during the scan,
argument validation and the invariant that observations authorize no
host write or package transaction.

## Acceptance and recovery limits

| Acceptance item | CI proof | Host status |
| --- | --- | --- |
| Late NGINX process after first preflight refuses native install | Must pass both native jobs with **no manager invoked for the refused attempt** | **NOT VERIFIED** on booted host |
| Fresh journal and lock rechecked before actual signed-source APT/DNF refresh and install | Must pass both native jobs with actual distro package transaction | **NOT VERIFIED** signed installed worker |
| Journal survives successful native package effects and blocks retry | Must pass with actual pending bytes and reentry refusal | **NOT VERIFIED** package-effect reconciliation |
| Actual fresh Debian13/Alma10 NGINX systemd operational, foreign instance preservation, repeated host install, reload failure restoring previous service | Not exercised | Original #27 **AC1–AC5 NOT VERIFIED** |

This is not a way to resolve the intentionally pending native package
journal. Its audited reconciliation and production-safe native first
installation must be combined with the independently reviewed #31/#64
root transaction and final booted #19 acceptance, not assumed from CI.
