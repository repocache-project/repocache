# Signed candidate acceptance — first operational v0.6.0

**Status (2026-11-07):** approved clean-install-only release target,
implementation proposed on #76 / PR #249, **final owner-signed release
acceptance NOT VERIFIED**. This document supersedes the historical
v0.5.0/v0.4.0 upgrade instructions in prior versions of this file. Those
historical instructions are preserved in Git history, not release gates.

## Applicable product boundary

The maintainer explicitly decided that no v0.4.0 instance is deployed and
**v0.6.0 cannot and will not upgrade from v0.4.0**. The immutable published
v0.4.0 remains historical and must not be mutated. Do not download, boot or
attempt to repair an old v0.4.0 executable as part of v0.6.0 candidate
acceptance. Refuse any unexpected previously installed state; an unapproved
migration is neither a clean install nor an implicit permission to erase data.
Same-version v0.6.0 repair, safe later updates, crash/recovery and rollback
remain in scope.

The new signed candidate publisher and source repository identity is always
`repocache-project/repocache`. The immutable old v0.4.0 signed
`teixemf/repocache` identity remains valid for historical verification
**only**, not as an alias in a fresh v0.6.0 signed manifest. The existing
owner-held Ed25519 key/fingerprint and **schema-1, eight-asset offline
wheelhouse** profile remain unchanged. Do not silently adopt the v0.7.0
online/source-only profile or source a publisher key from a candidate.

## Prepublication trust and acceptance — mandatory

1. Finish the working-server functional gates in #18/#19/#20/#24/#25/#26/
   #27/#28/#29/#30/#31/#64/#95/#97/#107. Preserve standalone CLI
   contracts and actual Debian 13 / AlmaLinux 10 NGINX, TLS, APT/DNF,
   systemd and enforcing SELinux requirements.
2. After approved integration, promote the reviewed release to protected
   `main` with separately authorized operations. Verify the actual
   **post-promotion main commit**, correct `v0.6.0` package/policy
   versions, frozen source and dependency locks, all required checks and
   application wheel/source correspondence.
3. Obtain separate owner approval to create the official `v0.6.0` tag
   and manually dispatch `.github/workflows/release.yml`. The owner-only
   `assemble` job must run successfully on the exact tag and upload
   `unsigned-release-candidate` using the officially pinned Node24
   `actions/upload-artifact`. Merely running a synthetic tests workflow
   is **not** this #74-G4 gate.
4. Independently retrieve the official uploaded unsigned artifact, verify
   its GitHub ID/digest, exact version/tag/main SHA, contents, archive
   provenance and fresh SHA-256 hashes. Record workflow/run/attempt, member
   list and checksums and obtain explicit owner acceptance of the actual
   #74-G4 upload/readback evidence **before signing**.
5. With *distinct* authorization on the trusted owner's workstation, use
   `scripts/offline_sign_release.py` / reviewed Release Operator for
   source/policy/wheel lock verification, protected encrypted Ed25519 key
   custody and exact owner signature. Private key/passphrase must never be
   sent to GitHub Actions, source control, chat or CI environment variables.
   Signing is not authorized by CI completion.
6. With another explicit owner authorization, stage **exactly eight** signed
   bytes as an unpublished GitHub Draft Release. Any missing, extra or
   overwritten asset must invalidate acceptance. Draft assets are mutable,
   and must be identified by both GitHub ID and SHA-256; do not Publish.
7. Manually dispatch `Signed release candidate acceptance` from protected
   main using exact `tag=v0.6.0`, `commit`, `draft_release_id`,
   `source_run_id` and `source_run_attempt`. The workflow validates
   source/tag/run ancestry, original owner actor, pinned public-key
   fingerprint, actual Ed25519 signatures, eight hashes, canonical
   source/workflow provenance and the signed **empty prior-version
   compatibility/downgrade lists**, before executing candidate code.
8. After authenticated readback, the two native distro-container jobs
   perform a **fresh initial signed v0.6.0 application install**, then
   same-version signed repair, tampered signed-wheel refusal, concurrent
   update locking, injected failure/rollback and preservation of NGINX,
   TLS, cache and APT/DNF fixture bytes. An actual fresh server's full
   native NGINX, systemd, TLS/cache HIT and SELinux-enforcing acceptance is
   a **separate mandatory host test**, not proven by those containers.
   No v0.4.0 install or upgrade is attempted.
9. The freeze job checks Draft identity and produces the exact candidate
   acceptance evidence. All **four** jobs must finish SUCCESS:
   `Signed draft publisher and asset identity`,
   `Clean install signed candidate (debian13)`,
   `Clean install signed candidate (almalinux10)`,
   `Freeze final candidate acceptance evidence`.
   FAIL, SKIPPED, missing evidence or stale source SHA blocks publication.

The CI workflow is read-only and uses only `contents:read` and
`actions:read`. Credentials must not follow CDN redirects; no publisher
private key or production service is present in CI.

## Publication authorization and immutable postpublication smoke

On a trusted terminal with an independently authenticated GitHub CLI:

```sh
GH_TOKEN="$(gh auth token)" python3 scripts/draft_release_gate.py guard \
  --ci-run-id REAL_SIGNED_CANDIDATE_ACCEPTANCE_RUN_ID
```

The guard must fetch the **actual immutable GitHub Actions evidence ZIP**,
verify its SHA-256/source workflow and all four successful jobs, and compare
all signed Draft asset IDs/hashes *again*. Even a successful guard does not
authorize publishing. Obtain a separate owner decision on the exact final
Draft and asset fingerprint. Immediately after explicitly authorized
publication, authenticate the immutable public v0.6.0 Release, its exact
source/tag, eight assets, signature, CDN bytes and anonymous runtime CLI
discovery, then perform a **fresh real public v0.6.0 install smoke**.
An immutable asset failure requires a new reviewed signed version; never
overwrite published assets or tags.

## Evidence, limitations and historical archive

Record **PASS / FAIL / NOT VERIFIED** per accepted criterion, exact SHA,
workflow/run/attempt, asset IDs/hashes, platform/Python/NGINX/kernel,
systemd/SELinux state, commands and redacted logs. Booted native host tests
cannot be inferred from Docker userspace. Real owner-key signing, Node24
artifact upload/readback, actual v0.6.0 Draft acceptance, two-OS full server
tests and postpublication smoke remain **NOT VERIFIED** until executed.

Issue #71 preserves historical v0.4.0 publication acceptance. Its old binary
cannot follow the later GitHub repository-transfer API redirect and is
deliberately **not** the active v0.6.0 test target. The manual
`public-release-acceptance.yml` may still authenticate historical signed
public v0.4.0 bytes; the retired native v0.4.0 runtime re-smoke is not
claimed PASS and is not a v0.6.0 compatibility requirement.

No document, script, successful synthetic test or owner scope decision
authorizes a merge, tag, signing operation, Draft staging, publication,
ruleset change, destructive migration or production service activation.
