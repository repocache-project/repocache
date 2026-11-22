# Release acceptance: candidate gates and published smoke

> **Maintainer-approved v0.6.0 first-install exception (2026-11-07):**
> The complete-server v0.6.0 is the first operational installation.
> The explicit owner instruction **removes the v0.4.0 -> v0.6.0 upgrade**
> and old-runtime compatibility gate, replacing it with genuine owner-signed
> v0.6.0 clean install, same-version repair, failure/rollback, native
> Debian 13 / AlmaLinux 10 and safe legacy-state refusal. No v0.4.0
> API redirect repair, migration or old executable execution is required.
> This is NOT a general waiver of future upgrade safety, #76/#88 security,
> owner-controlled signing/publishing, or Node24 #74-G4 upload/readback
> and explicit owner acceptance. The schema-1 eight-asset offline
> wheelhouse and pinned Ed25519 key remain the signed release baseline.
> Historical v0.4.0 source/release evidence is preserved immutable.
> See #25/#76/#88 and [v0.6.0 release target](RELEASE_TARGET_V0.6.0.md).


This policy applies to subsequent releases. First-public v0.4.0 is special:
there was no earlier public REPOCACHE distribution against which the public
update and installation pipeline could be tested. This is not permission to
publish future releases before exercising their signed installers.

## Version-independent stabilization and final source identity

For every selected stable `vX.Y.Z`, run feature acceptance on
`integration/vX.Y.Z` and optionally alpha/beta host trials on the frozen
`release/vX.Y.Z`, without claiming those preliminary test artifacts are
the signed final candidate. The protected `main`/release rulesets currently
require linear history and permit squash/rebase promotion; these methods may
rewrite the source commit. **Promote first, then verify the resulting protected
`main` source SHA, authorize the official stable tag and only afterwards
perform the genuine owner-signed candidate Stage A against that exact SHA.**
The signed candidate must be accepted before Stage B publication.
There is no default alpha/beta signing, publication or production activation.
Follow [the generic lifecycle](RELEASE_LIFECYCLE.md) and preserve the actual
version-specific signed trust/baseline policy (issue #76).

## Stage A: release candidate (prepublication, mandatory for v0.5.0 onward)

1. Freeze the reviewed commit, compatibility policy and dependencies.
   For the clean-first v0.6.0, require no accepted prior version; any
   v0.4.0 or other unsupported existing state must be refused safely.
   Later release versions require their own explicitly approved compatibility
   matrix and true upgrade tests before publication.
2. Produce reproducible candidate source archive and offline wheelhouse.
   Authenticate the exact FINAL candidate with the genuine offline publisher
   signature and an independently provisioned trust anchor, not a disposable
   CI signing key. Never place the signing private key in GitHub Actions.
3. Before extracting or running candidate code, verify signatures, source
   digest, signed policy, runtime wheelchain hashes, SBOM and lockfile.
4. On disposable Debian 13 / Python 3.13 and AlmaLinux 10 / Python 3.12
   systems: clean install, selected version, same-version repair,
   rootless privileges, journal recovery,
   rollback, concurrency and failure injection. Preserve NGINX/TLS/APT/DNF.
5. Reject incompatible and unsupported downgrade paths, including all
   unapproved private/pre-public migration attempts.
6. Map EVERY acceptance criterion to executed PASS/FAIL/NOT VERIFIED evidence.
   Any applicable FAIL or NOT VERIFIED prevents release authorization.

For v0.5.0 onward, the read-only signed candidate staging/gating
implementation is described in docs/SIGNED_CANDIDATE_ACCEPTANCE.md
(issue #76): owner signs verified exact-final artifacts outside GitHub,
stages the eight bytes in a mutable private GitHub Draft Release, and
dispatches the signed-candidate-acceptance.yml workflow on protected main.
Its accepted native-container tests and immutable Actions acceptance
artifact are prerequisites for the separate operator publication approval.

This workflow and publication guard cannot be declared **end-to-end PASS**
until a real owner-signed v0.6.0 candidate and Draft Release exist. The
private draft is not an immutable public endpoint, and a successful
workflow alone does not prevent an administrator from overriding the
manual publication process. Any draft asset change after the CI jobs
invalidates their acceptance.

## Stage B: published smoke (mandatory immediately after every public release)

1. Discover the official stable version anonymously through the GitHub API.
2. Read back exact release ID, immutable=true, tag, source commit, eight
   approved public asset identities, sizes and SHA-256 hashes.
3. Download the actual public assets, verify independent public-key fingerprint,
   real Ed25519 manifest/provenance signatures, code and wheelhouse identity.
4. Run the real REPOCACHE discovery CLI and fresh native public
   v0.6.0 install smoke; record exit codes and host identity.
   Do not attempt an unsupported v0.4.0 -> v0.6.0 upgrade.
5. Report PASS/FAIL/NOT VERIFIED with a concrete workflow/run. If broken,
   investigate and publish a newly reviewed signed version, never rewrite
   immutable release assets or tags.

For unique first-public v0.4.0, issue #71 explicitly also requires the
DEEPER real CDN-backed installation, repair and negative tests that could not
be exercised before the original public publication.

## Automation and trust boundary

- .github/workflows/public-release-acceptance.yml: manually dispatched
  historical v0.4.0 **signed asset readback only**, not current legacy runtime
  installation smoke or a v0.6.0 release gate. The obsolete v0.4.0 executable
  rejects the transferred old GitHub API redirect. A separately approved
  genuine v0.6.0 postpublication public/CLI smoke is mandatory.
- scripts/public_release_targets.json: pinned independent reviewed asset ID,
  hash, commit and publisher fingerprint. Future versions must be separately
  approved via PR and explicitly selectable from the workflow inputs.
- scripts/public_release_acceptance.py: anonymous HTTPS API and CDN reads;
  check immutable release, exact tag/run, all local hashes and detached
  signatures before extraction or any publisher-supplied code execution.
- scripts/ci_public_release_native.py: **historical** v0.4.0 release
  acceptance tool retained for archival reproducibility; do not run it as
  a v0.6.0 candidate gate. Active owner-signed v0.6.0 native acceptance
  belongs to scripts/ci_signed_candidate_native.py and the protected
  signed-candidate workflow.
- tests/test_public_release_acceptance.py: mock-only parser and refusal tests;
  these NEVER count as successful native/real-network acceptance.

Use pinned Actions SHAs, contents:read permissions, no credentials persisted
by checkout, no publisher private key, and unprivileged actual application
execution. No tests are authorized to mutate a published Release or
production system. Container tests are NOT real booted-systemd or host-SELinux
tests; physical power-cut remains NOT TESTED as accepted for the first release.
