# NGINX native VM prerequisites — one-line copy/paste receipt (#27)

**Purpose:** capture an easy-to-share, *read-only* observation of the
NGINX/systemd/SELinux prerequisites for the final #19 native test campaign,
without asking the maintainer to upload files or expose hostnames, PIDs,
TLS paths, package cache data, credentials or private release metadata.

This is **not an installed server acceptance test**. The production
root-worker, owner-signed release, operator permissions, protected
state-v2 migration, service activation/rollback, native package journal
reconciliation and full #27 original acceptance criteria are separate
gates. Nothing in a pasted receipt authorizes installation or publication.

## How to obtain a line when VM testing is explicitly ready

On a booted **Debian 13 x86_64** or **AlmaLinux 10 x86_64** VM under an
operator-approved and verified source checkout, from an already-established
root shell that is authorized to run *reviewed read-only* checks:

```sh
PYTHONPATH=src python3 -B scripts/inspect_native_vm_nginx_prerequisites.py |
  python3 -B scripts/format_native_nginx_vm_paste_receipt.py
```

Copy and paste **only the single output line** beginning with
`REPOCACHE_NGINX_VM_V1=` in the existing #27/#19 discussion, or into the
current conversation. There is no need for an uploaded file. The
formatter deliberately exits with status **2**, even when every
*read-only prerequisite* is observed; this is **not a failed server
installation** or a GO signal. The observer itself may return status 2
when prerequisites are not met. Prefer an interactive shell without
`set -e` for this observation pipeline.

Do **not** run an unverified checkout as root, install or start NGINX
as part of this diagnostic, or substitute a privileged Docker container
for the native VM. The tester, not the formatter, is responsible for
verifying exact source provenance, kernel/OS identity and evidence
authenticity. The report cannot prove that it was run on a real native
VM rather than generated synthetically.

## Strict redaction and fail-closed model

The formatter consumes at most 4096 input bytes from stdin and accepts
only the exact version-1 object emitted by the existing
`inspect_native_vm_nginx_prerequisites.py` reader. It refuses duplicate
JSON keys, unknown attributes, invalid UTF-8, unexpected versions,
malformed status/code/distribution combinations, nonsensical booleans
and *any* input claiming signed host authority, root attestation,
complete server acceptance or permission to mutate services.

Only the following categories reach its one-line output:

- Supported `debian`/`almalinux` distribution and named fixed refusal.
- Whether supported Python/OS, PID1 systemd namespace shape, AlmaLinux
  SELinux enforcing, and effective stock NGINX master were *observed*.
- Unconditional `status: NOT VERIFIED`, `issue_27_acceptance_passed:
  false` and negative host/NGINX/publication authority.

It **never** prints source strings other than those enumerated constants,
raw input, a PID, hostname, host path, URL, package manager output,
certificate, SSH/TLS material, state, tokens or kernel namespace IDs.
Unexpected input produces a single fixed `INPUT_REFUSED` line.

A positive `OBSERVATION_ONLY_NO_HOST_AUTHORITY` only means that the
read-only inspector reported a necessary set of fixed properties. It
cannot attest an installed release, actual NGINX listener reachability,
native package provenance, unexpected concurrent service changes,
idempotence, application routing, rollback, SELinux policy correctness,
or all original issue #27 acceptance requirements.

## CI evidence expected

The workflow `.github/workflows/server-v06-nginx-vm-paste-receipt.yml`
runs unmodified native distro userspaces in disposable Docker images
with a read-only source mount. It executes the *real* read-only
inspector and passes its JSON through the formatter. Both jobs must
emit `CONTAINER_CONTEXT_REFUSED`, an explicit
`issue_27_acceptance_passed:false` and nonzero exit; positive VM
or release acceptance must never be observed in CI containers.

Focused no-host regression command:

```sh
PYTHONPATH=src python3 -m pytest -q tests/test_native_nginx_vm_paste_receipt_v1.py
```

The tests also feed synthetically positive but non-authorizing native
observations and adversarial forged, partial, oversized, duplicated,
privileged or secret-bearing inputs. Success is limited to **redaction,
formatting and refusal semantics**; no host systemd/SELinux validation
or publication acceptance is claimed.

## Native #27 acceptance ledger

| Original criterion | Covered by this report? |
| --- | --- |
| Fresh Debian 13 operational NGINX | Only a necessary *read-only* PID1/unit observation; **NOT VERIFIED** |
| Fresh AlmaLinux 10 operational NGINX with enforcing SELinux | Same limited native observation; **NOT VERIFIED** |
| Reinstall idempotence | Not exercised; **NOT VERIFIED** |
| Preserve/refuse foreign NGINX | Not a complete ownership manifest; **NOT VERIFIED** |
| Recover previous working state after failed NGINX syntax/reload | No service mutation or health test; **NOT VERIFIED** |

Retain #27 open until the independently accepted #31/#64 privileged
implementation and real booted #19 tests establish the original full
criteria at the exact reviewed revision.
