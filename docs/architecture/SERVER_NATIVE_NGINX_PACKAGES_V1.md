# Inert native NGINX package preview v1 (#27)

**Status:** initial source-only, non-authorizing implementation. This document and
server_native_package_plan_v1.py do **not** deliver native package verification,
NGINX installation or server provisioning.

## Fixed package intent

| Supported host | Native manager | Distribution-supplied package |
| --- | --- | --- |
| Debian 13 / Python 3.13 | APT | nginx |
| AlmaLinux 10 / Python 3.12 | DNF | nginx |

The preview_nginx_packages function revalidates the closed v1 install schema
and native OS/Python identity, then returns only the fixed package selection
and five **NOT VERIFIED** gates. The operator cannot submit package names,
shell commands, repositories, trusted keys or flags through
deployment.native_packages, which permits only policy=explicit-review. The
package list is a reviewed target, not proof that a package is available,
authentic, current or safe to install.

The report is deterministic, contains only static English remediation and
allowlisted package names, and always returns can_install=false,
all_verified=false and authorizes_installation=false. It never invokes
APT/DNF, refreshes metadata, contacts a network service, writes files,
checks package trust, claims NGINX ownership or asks for privilege. It is not
yet wired into the public deployment preflight command, which remains a
separate partial, permanently non-authorizing observation.

## Mandatory downstream execution boundary (not implemented)

Before a privileged native transaction (#27), implement and separately test
all of the following, failing closed with redacted actionable errors:

1. Check effective supported OS, system Python and existing/unmanaged NGINX
   conflicts on the actual host. Never take over a third-party NGINX service.
2. Review enabled distribution-approved APT/DNF sources, provenance of
   trusted signing keys, and effective native repository/package signature
   verification. Reject third-party substitutions, trusted=yes, unsigned
   sources, gpgcheck=0, repo_gpgcheck=0 where required by approved policy,
   disabled verification, unavailable or stale metadata and offline failures.
   Native APT/DNF is authoritative; do not build a second signature verifier.
3. Verify the exact selected nginx package's availability and trusted native
   source, reporting missing/untrusted packages without leaking repository
   credentials or unreviewed source URLs. Any planning-time results may be
   stale and are **not** install approval.
4. On a **separately authorized** privileged operation, repeat the relevant
   trust and availability checks; document irreversible native package effects
   and handle partial transactions (#31). Reject failed checks before any
   NGINX/REPOCACHE configuration, service, TLS or firewall activation.
5. Only after existing-NGINX ownership, staged complete-context nginx -t,
   rollback and controlled reload gates have been proved, perform separately
   approved service activation. Preserve the previous configuration on failure.

The original #27 criteria remain NOT VERIFIED: booted Debian 13 and AlmaLinux
10 installed NGINX service acceptance, re-run idempotence, no third-party
adoption, failed config/reload recovery and systemd/SELinux behavior. Tests of
this pure preview cannot satisfy those operational criteria, nor #26's
missing-package diagnostic acceptance. Do not close #26, #27, #18 or #25 based
on this source-only increment.
