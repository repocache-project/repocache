# REPOCACHE v0.6.0 server operator guide

The v0.6.0 target is a fresh managed cache server. The current source checkout
provides the read-only preflight and evidence tools described below. Complete
installation, service activation, same-version repair and recovery still
require verified native acceptance in [issue #19](https://github.com/repocache-project/repocache/issues/19).
Use the [v0.4.0 existing-NGINX guide](PRODUCTION_EXISTING_NGINX.md) for the
published frontend on an operator-managed NGINX server.

| Target | Native prerequisites |
| --- | --- |
| Debian 13 (x86_64 / native amd64 packages) | OS Python 3.13, APT, distribution NGINX and booted systemd |
| AlmaLinux 10 (x86_64) | OS Python 3.12, DNF, distribution NGINX, booted systemd and SELinux enforcing |
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

## Choose the right supported deployment path (#20)

**Fresh v0.6.0 target (not yet shipped):** a reviewed, clean-install-only
server candidate on **x86_64** Debian 13 or AlmaLinux 10, with native APT/DNF
NGINX, protected managed state, operator-provided TLS and explicit
administrator-approved repository mappings. A read-only preflight can run
today; a preflight PASS-like observation, a rendered NGINX candidate or
a green CI workflow is **not** a working provisioner or installation
approval. Do not invoke hypothetical `deployment install` or
`repos add` commands as though they had been released. Their
full privileged lifecycle and booted-host acceptance are still tracked by
#19/#26/#27/#28/#30/#31/#64/#95.

**Existing independently configured NGINX:** the published v0.4.0
`install.sh` contract installs a frontend, not native infrastructure
and not a full v0.6 server. Follow
[the v0.4.0 existing-NGINX guide](PRODUCTION_EXISTING_NGINX.md)
for that separately owned service. The v0.6 candidate must **refuse**
unreviewed pre-existing NGINX processes, units, includes and conflicting
ownership; never import its TLS keys, overwrite its routes, enable a new
listener or replace its package-managed systemd unit merely because a
configuration file parses. Stop if ownership is uncertain, preserve original
inodes and bytes, and restore from an independently verified snapshot.

**Unsupported host:** Debian 12 or older, AlmaLinux 9 or older, other
distributions/derivatives, non-x86_64 CPUs, wrong OS Python, containers
claimed as booted hosts and unexpected NGINX owners are not migration
shortcuts. Refuse native infrastructure changes until preflight and
ownership acceptance identify a supported clean target. An existing
v0.4.0 server is not implicitly authorized for an in-place v0.6.0
migration just because the next public-version compatibility gate must
separately prove the authentic published v0.4.0 transition.

## Application/dependency provenance and offline operation (#20)

The selected v0.6.0 release baseline remains the **reviewed
owner-authenticated, eight-asset, legacy offline-wheelhouse candidate**
from the [release target](RELEASE_TARGET_V0.6.0.md) and the
[signed-candidate contract](SIGNED_CANDIDATE_ACCEPTANCE.md),
subject to final candidate-specific evidence. The historic v0.5.0 signing
examples are **not** authority to accept a v0.6.0 tag without its distinct
review. Owner-held Ed25519 private keys and passphrases stay on the
authorized signing workstation, never on an installer host or GitHub CI.
Obtain publisher public-key trust independently of downloaded source
and verify the exact reviewed manifest, source, wheelhouse, dependencies,
platform tags, SBOM, notice files and SHA-256 identities **before** executing
candidate-supplied software. A source or wheel hash alone is not the
publisher's signature.

**Separate first-party and third-party trust:** the REPOCACHE application
wheel is part of the owner-signed candidate. External Python wheels retain
their own upstream bytes, individual hash/ABI lock, license grants and
notices. The CI
[native upstream wheel test](CI_NATIVE_UPSTREAM_WHEELS_V06.md)
downloads pinned public PyPI wheels **only** as a disposable compatibility
experiment with a legacy lock; it is not an approved online runtime installer,
not a new signed v0.6.0 source-only profile and not proof of a real
publisher-approved dependency lock. Avoid silently mixing these profiles.

Do **not** permit source distribution builds, implicit transitive
resolution, floating versions, unpinned fallback, arbitrary package indexes,
unreviewed CA bundles, pip configuration inherited from a user account,
root-wide pip writes or service-account privilege escalation. A future
separately approved online dependency path must use the exact independently
reviewed index/CA allowlist, pinned wheel hashes, a bounded non-root
generation-specific virtualenv, redacted downloads/logs and its own
isolation/activation acceptance. Do not print index credentials, URL tokens,
TLS private keys or internal repository addresses. These future controls
are not implied to be operational in v0.6.0.

A PyPI outage is **not** authorization to loosen hash, TLS, signature or
version checks. With the authenticated offline wheelhouse already available,
Python dependency installation must not need a live PyPI fetch; native NGINX
package installation, authentic APT/DNF upstream metadata and a missing
signed release asset have **separate** availability and trust constraints.
If required authenticated assets or distro packages are unavailable,
report the bounded failure and preserve the prior working installation;
do not substitute unofficial mirrors automatically.

Review [third-party notices and rights](THIRD_PARTY_RIGHTS_REVIEW.md)
with the **actual final asset set**. Licenses and redistribution obligations
continue under the individual grants; downloading dependencies does not
transfer legal responsibility automatically to an upstream registry.
The reviewed software supply-chain and legal notices must accompany the
published artifact when required. This guidance is not legal certification.

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
