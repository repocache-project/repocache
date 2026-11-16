# Native candidate identity receipt — final booted VM preparation

**Owner:** #19, final clean Debian 13 / AlmaLinux 10 acceptance campaign.
**Stage:** executable Stage-A source/CI tooling; **NOT** final VM, publisher,
systemd, installed package-manager or SELinux acceptance. The release
candidate and owner signing/publishing decision must stay separate.

The source code is at `src/repocache/native_acceptance_evidence_v1.py`,
with a non-mutating operator wrapper at
`scripts/collect_native_candidate_evidence.py`. The tool reads one
explicitly named candidate from a pinned, non-symlinked, single-link
regular file; refuses group/other writable, oversized and path-redirected
assets; computes actual SHA-256, compares an explicitly supplied expected
digest, and uses only the existing fixed read-only booted-native NGINX
preflight. It never opens private signing keys, queries GitHub, fetches
network data, changes permissions, writes files or controls any service.

## Planned final campaign use

Run the command **only on the assembled exact candidate** already identified
by the authorized release process. Pin both the candidate SHA-256 and the
matching source commit first, and verify the artifact's **real owner-held
Ed25519 signature separately**. Example (nonproduction placeholders):

```sh
export PYTHONPATH=src
python3 -B scripts/collect_native_candidate_evidence.py \
  --candidate /srv/staging/repocache-v0.6.0.tar.gz \
  --sha256 YOUR_EXPECTED_64_LOWERCASE_HEX_SHA256 \
  --source-sha YOUR_EXACT_40_LOWERCASE_HEX_COMMIT
```

The wrapper emits deterministic JSON to stdout with no original path,
hostname, token, certificate, private key or source-file contents.
A wrong digest produces status `FAIL` and exit 1. A matching digest
produces status `NOT VERIFIED` and exit 2 **even on a booted VM**:
the receipt is an identity observation, *never* an authorization or
complete-server acceptance. A missing/replaced/symlinked asset also
returns `NOT VERIFIED`/exit 2. Bad arguments return fixed `FAIL`/exit 1.
There is **no exit-zero release certification**.

At the final VM checkpoint, collect (and redact) a separate per-criterion
evidence ledger: booted target identity and SELinux mode, exact candidate
and verified signing fingerprint, owner-reviewed native package inventory,
actual root-owned installed files and systemd/NGINX state, listening TLS
policy, APT/DNF signed metadata and package payload download, repeated
cache HIT/hash, upstream fallback, actual admin opt-in client sync, repair,
interruption/recovery, negative/foreign ownership and unsupported OS
no-write cases. Every original requirement must have its own witnessed
PASS/FAIL/NOT VERIFIED with source SHA, artifact checksum, VM identifier,
commands, logs and operator review.

**A matched SHA-256 is not publisher identity.** A malicious candidate
can carry the expected digest if an untrusted source supplied that digest.
The tool intentionally reports
`publisher_signature_verified=false`,
`source_commit_authenticity_verified=false`,
`installed_artifact_verified=false`,
`complete_server_acceptance_passed=false`, and every
`authorizes_*` field false, including when a synthetic native prerequisite
probe reports success.

## Automated acceptance before requesting VMs

`tests/test_native_acceptance_evidence_v1.py` covers correct and wrong
hashes, malformed source SHA, symlinked/hardlinked/g-writable and too-large
assets, lack of native evidence, forged positive probe responses and
sensitive path redaction. The existing
`.github/workflows/server-preflight-distro.yml` runs the CLI and tests in
both disposable Debian 13 and AlmaLinux 10 containers and asserts these
containers cannot become a booted-native PASS.

This runbook is a **preparatory** deliverable, not the full VM script or an
early request for maintainer VM effort. It neither extends the milestone
scope nor closes #19, #25, #24, #76 or #88.


## Contradictory native observations fail closed (#19)

The source-only candidate receipt now accepts a positive read-only native
prerequisite observation **only** when the fixed probe simultaneously reports
`READ_ONLY_PREREQUISITES_OBSERVED`, the exact non-authorizing code
`OBSERVATION_ONLY_NO_HOST_AUTHORITY`, and both required native-shape Booleans.
A contradictory refusal code (for example, a container or failed systemd
probe) cannot become an apparent positive merely because an untrusted caller
set the other fields to true. Negative regression tests cover this case.
Even the matching code comes from a caller-provided probe, is not a signed
host attestation and **never** changes the overarching `NOT VERIFIED`
release status or any authorization field. Booted VM, owner signing and
package-manager acceptance remain mandatory and separate.
