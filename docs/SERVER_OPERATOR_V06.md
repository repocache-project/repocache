# REPOCACHE v0.6.0 server operator guide

The v0.6.0 target is a fresh managed cache server. The current source checkout
provides the read-only preflight and evidence tools described below. Complete
installation, service activation, same-version repair and recovery still
require verified native acceptance in [issue #19](https://github.com/repocache-project/repocache/issues/19).
Use the [v0.4.0 existing-NGINX guide](PRODUCTION_EXISTING_NGINX.md) for the
published frontend on an operator-managed NGINX server.

| Target | Native prerequisites |
| --- | --- |
| Debian 13 | OS Python 3.13, APT, distribution NGINX and booted systemd |
| AlmaLinux 10 | OS Python 3.12, DNF, distribution NGINX, booted systemd and SELinux enforcing |
| Debian 12 and earlier, AlmaLinux 9 and earlier, other distributions | Unsupported |

## Prepare a clean host

1. Use a fresh supported host with a recoverable snapshot. Include any
   separate data volumes in the recovery plan. Verify capacity and mount
   writability for persistent state, cache and logs.
2. Plan an HTTPS listener and DNS name, and provision a matching operator-owned
   certificate, chain and protected private key. Transfer public trust
   material through the operator's trusted channel. Keep the key out of
   source control, CI and REPOCACHE service-account access.
3. Review the [installation contract](architecture/SERVER_INSTALLATION_CONTRACT_V1.md)
   and copy the [install-v1 example](examples/server-install-v1.json) into
   a locally controlled regular file. Replace the placeholder DNS and repository
   entries with operator-approved HTTPS origins and public repository key
   references. Review paths, listener intent and cache policy. The example's
   `.invalid` names are deliberately unusable.
4. Obtain the exact reviewed release source SHA, source-archive SHA-256 and
   independently provisioned publisher public key fingerprint. Verify the
   signed manifest and hash-pinned native offline wheelhouse before running
   code from the candidate. Native APT/DNF package trust and upstream
   repository metadata/payload trust are separate checks.

v0.6.0 has a clean-install-only entry path. Existing v0.4.0 or earlier
REPOCACHE state and external NGINX ownership require preserving the current
installation and selecting a separate clean host. If a managed include,
state directory or service already exists, establish its ownership and
provenance before selecting a recovery or repair operation.

## Run the read-only preflight

From the reviewed source checkout, use the host's system Python. The
document path must be absolute and the file and its ancestors must pass
the input checks.

```sh
/usr/bin/python3 -I scripts/server_v06_preflight.py \
  --document /absolute/path/to/reviewed-server-install-v1.json \
  --intent inspect
```

The command emits one JSON report. Exit 1 means a failed check, exit 2 an
invalid input or unavailable observation and exit 3 an incomplete assessment.
The report always sets `authorizes_installation` to false. Run it again after
correcting the condition. See the [distro preflight runbook](testing/SERVER_VM_PREFLIGHT_V06.md).

| Observation | Operator action |
| --- | --- |
| Unsupported OS or Python | Use the distribution-provided interpreter on a supported host. |
| Native package missing or native trust unverified | Check the allowlisted distribution sources, signing key and current metadata through the separate [#27 preparation flow](architecture/SERVER_NATIVE_NGINX_PACKAGES_V1.md). Keep APT/DNF signature verification enabled. |
| NGINX executable, include or listener conflict | Identify the current owner and use a clean deployment target when ownership is external or cannot be established. Preserve the existing service and rules. |
| TLS material refused | Confirm the reference, parent ownership, file type and mode, certificate expiration and hostname, matching key and trusted chain. Keep private key contents out of diagnostics. |
| AlmaLinux SELinux prerequisite unverified | Keep enforcement enabled. Check the package policy and managed path labels through the reviewed native procedure. |
| Too little storage, exhausted inodes or a read-only mount | Check byte and inode headroom and writability for state, cache and log mounts. Re-run the preflight after recovering the specified storage. |

## Installed-system acceptance and recovery

Run the final [#19 campaign](https://github.com/repocache-project/repocache/issues/19)
only with the exact authenticated installation candidate, reviewed procedure
and one disposable booted target per distribution. Record the starting
snapshot and the baseline of protected paths, service state, TLS identity,
repository access and selected cached bytes. Collect the following evidence
for each target.

| Operation | Required observation |
| --- | --- |
| Fresh installation | Native package provenance, root-owned managed files, exact loaded systemd units, successful NGINX syntax check, healthy HTTPS and AlmaLinux enforcing labels. |
| Repository activation | Authorized active-only discovery, native APT/DNF signature verification and matching metadata and payload bytes. Observe a MISS followed by a HIT. |
| Client outage/fallback | Use separate disposable client state. Confirm native upstream access and signature enforcement during the cache outage and check recovery when service resumes. |
| Repeat or same-version repair | Reauthenticate the exact candidate. Compare managed generation, configuration, certificate identity, cached bytes and historical logs before and after. |
| Failed activation or interruption | Verify the previous generation, working HTTPS and the corresponding catalog together. A successful syntax check or reload exit alone cannot establish the active generation. |

If managed recovery reports `NEEDS_RECONCILIATION` or the observed service
and catalog disagree, stop automated changes. Preserve the journal and
last-known-good managed generation, then use the reviewed #31 recovery
procedure. Package-manager side effects require separate reconciliation.
Restoring a managed NGINX include or application generation cannot undo
those effects. Leave unrelated includes, TLS material, cache files and
client sources under their existing ownership.

Use the [compact VM receipt](testing/NATIVE_VM_PASTE_RECEIPT_V06.md) to share
candidate identity and the read-only observation without a file upload.
Record each executed check as PASS, FAIL or NOT VERIFIED and attach only
sanitized evidence when more detail is required. The compact receipt is
partial evidence. The signed install, booted systemd, SELinux enforcement
and recovery outcomes need their own observations.

## Evidence available in CI

The [preflight suite](testing/SERVER_VM_PREFLIGHT_V06.md) runs in Debian 13
and AlmaLinux 10 containers. Real stock NGINX exercises
[HTTPS and TLS](testing/SERVER_MANAGED_TLS_NATIVE_SMOKE.md),
[reload refusal and recovery](testing/SERVER_NATIVE_NGINX_RUNTIME_RELOAD_REFUSAL.md)
and [signed repository caching](testing/SERVER_DYNAMIC_SIGNED_NATIVE_REPOSITORIES_V1.md).
The [journaled package rehearsal](testing/SERVER_V06_JOURNALED_NATIVE_INSTALL.md)
uses real distro packages in disposable containers. The full booted install
guide, release-candidate repair and site recovery remain NOT VERIFIED until
the final campaign.
