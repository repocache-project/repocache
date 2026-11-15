# Correlated postpackage NGINX evidence — Stage A (#27/#31)

Before #31 can finalize an actual NGINX install it must reconcile **native
APT/DNF package effects**, which are not reverted by its ordinary atomic JSON
state journal. The existing durable native-effects pending marker therefore
blocks repeat attempts after a real package transaction, including interruption.

The new \`inspect_current_namespace_native_postpackage_candidate\` joins
three existing, independently bounded observations in a **read-only**
sequence:

1. Check the canonical pending native-effects marker in the protected state
   namespace and its explicit reentry block.
2. Read exactly the installed \`/usr/sbin/nginx\` package owner through
   fixed \`dpkg-query\` or \`rpm\` commands (not signature verification).
3. Inspect the fixed stock \`nginx.service\` vendor-file shape, rejecting
   substitutions, shadow units, unsafe permissions and unknown directives.
4. Re-read the pending marker and reject a changed or ambiguous report.

The new actual **disposable Docker** installed-package CI stage exercises the
same correlator after installing native NGINX under the retained journal lock.
It does not invoke a booted systemd PID 1, install a root broker, clear a
journal, accept real publisher signatures, change SELinux or grant reload.
The two journal reads cannot supply an atomic transaction lock across the
package-owner and vendor-unit reads; this result is only diagnostic evidence
for the *future* audited native state transition.

**Required next:** an independently reviewed authenticated host-root
transition under one held #31 lock, with signed native package provenance,
package/service ownership, SELinux, durable state + NGINX rollback and
operator authorization, respecting #64. Do not clear the pending journal,
re-run the native package manager, or activate NGINX on a production host
merely because this diagnostic returns a candidate.
