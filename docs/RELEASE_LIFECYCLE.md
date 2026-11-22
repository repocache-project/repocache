# Release lifecycle — any maintainer-selected stable vX.Y.Z

**Process decision (2026-11-03):** the maintainer chose separate integration,
stabilization and stable-source lanes for every future version. This document
specifies the workflow without silently approving any feature, milestone,
version tag, private-key operation, merge or release publication. It does
not rewrite historical v0.4.0 provenance. Public v0.5.0 was canceled; next
public target is v0.6.0 (complete working Debian 13 / AlmaLinux 10 server).

**Adoption:** apply this routing only after the relevant workflow and
documentation PRs are accepted and merged on the protected source branch.
A draft/unmerged policy is not an effective rule. The current default-branch
workflows and effective GitHub rulesets are the operational authority.


## Adopted routing and session continuity (verified 2026-11-09)

The one-time bootstrap sequence (PRs #230, #183 and #231) is **historical migration context**, not an ongoing pause condition. Protected `main` was verified at `63fae6adada334492081c598a3045f238f40a7c6` (PR #245); `integration/v0.6.0` at `d53782ed01e1f85686f10279fd3c7eea6d7f6720`; and `integration/v0.7.0` at `8c43d6b1fefd101f46ffb8a199ceff2c82f7c957`. Both active integration lanes received the required `merge_group` triggers through PRs #242/#243. Successful `merge_group` runs on 2026-11-07 do not prove native-host, publisher signing, negative queue tests or release acceptance.

Check current target heads, rulesets and CI when resuming. If one lane's required checks or acceptance are missing, block **that integration**, not independent approved work. Future release routing remains constrained by the maintainer-selected version, actual protected branch rules and original acceptance.

## Universal acceptance scheduling

For any `vX.Y.Z`, use the
[three-stage implementation/native/publisher model](ACCEPTANCE_STAGES.md).
Complete approved, CI-verifiable Stage-A implementation on the selected
`integration/vX.Y.Z` lane first; do not wait for the final native campaign
to integrate genuinely non-activating, fully accepted code. Prepare the
complete booted-VM acceptance runbook before a release cut and consolidate
the necessary Stage-B host tests on the assembled installable candidate.
The stabilization and publisher sequence below is unchanged: no Stage-A
merge implies release readiness, final signed identity or approval to
promote to `main`. An issue-specific pre-merge native/security criterion
remains mandatory unless an authenticated maintainer scope amendment
explicitly authorizes a narrower Stage-A deliverable.

## Branches and allowed changes

| Ref | Purpose | Allowed changes |
| --- | --- | --- |
| `feat/*`, `fix/*`, `ci/*`, `docs/*`, `test/*` | Focused working branches | Issue-scoped changes with test evidence and PR |
| `integration/vX.Y.Z` | Version-specific functional integration | Individually accepted feature PRs and necessary backports |
| `release/vX.Y.Z` | Frozen stabilization candidate, optional lab alpha/beta | Only essential reviewed fixes, tests and acceptance evidence |
| `main` | Stable source and official release ancestry | Separately approved release promotions and emergency hotfixes |
| `refs/tags/vX.Y.Z` | Official stable immutable source identity | Created only after `main` promotion, with separate owner approval |

The version is the maintainer-selected canonical stable `vMAJOR.MINOR.PATCH`
identifier; this is a template for any future release, not a list of
hard-coded versions. For each release, record the actual version, issue
milestone, approved scope, dependencies and baseline, and inspect current
branch rules. Existing historical refs, including `integration/v0.5.0`
and `release/v0.4.0`, are retained for audit without repurposing them.

## Ordered execution

1. **Plan and select version.** The maintainer expressly defines the next
   public target and its release acceptance scope. Create or select the
   correctly governed milestone; do not move existing issues or add
   requirements automatically.
2. **Integration.** Establish `integration/vX.Y.Z` from the verified
   accepted baseline. If work depends on another still-open integration
   lane, reconcile dependencies explicitly rather than copying unfinished
   code. Send feature PRs to this lane, not `main`. Verify nine required
   check contexts and full original applicable criteria on the exact HEAD.
   The live `integration/*` ruleset controls updates.
3. **Stabilization cut.** Once feature scope is accepted for the release,
   create `release/vX.Y.Z` at a specifically approved integration commit.
   Freeze feature additions. Permit only minimal separately reviewed
   candidate fixes and native operational acceptance. The live
   `release/*` ruleset controls updates. Re-run tests after every change.
4. **Optional pre-release host trials.** A bounded `alpha` or `beta`
   experiment may install a byte-identifiable candidate from the release
   branch on disposable or purpose-built Debian 13 / AlmaLinux 10 machines,
   with owner approval for the test environment and explicit rollback.
   Record the source SHA, asset hashes, host OS/kernel/systemd/SELinux,
   commands, outcomes and failures. These are **not** stable releases or
   replacements for owner-signed final acceptance. Do not reuse production
   signing keys for improvised test artifacts or expose production services.
   No prerelease tag, GitHub publication, production deployment or new
   artifact profile is implicitly authorized. Skipping alpha/beta is valid.
5. **Promote to protected main.** Complete the stabilization-stage criteria
   before opening a release-to-`main` PR. GitHub's current `main` and
   `release/*` ruleset requires **linear history** and allows only
   `squash` / `rebase` PR merges. Consequently a promotion may produce
   a **new source commit SHA**, even if file contents are identical. Recheck
   all required contexts, source identity and applicable change acceptance
   on the resulting protected `main` commit. Never claim the older
   release-branch commit itself was merged unchanged if it was rewritten.
6. **Freeze final source and build.** Only the newly verified protected
   `main` source is eligible for the official stable tag. A separate
   owner authorization is required for that exact tag/SHA and manual
   `.github/workflows/release.yml` dispatch. This existing workflow
   enforces that the tagged source is an ancestor of `main`, that the tag
   matches the packaged project version, and that it only produces an
   **unsigned** candidate; it does not sign or publish.
7. **Authenticate, sign and accept.** Apply the actual version-specific
   signed-candidate and compatibility policy, genuine owner-held Ed25519
   signature, official unsigned build run and independent #74-G4 readback.
   Execute the full #76/#88 genuine signed-candidate installation,
   v0.4.0-to-v0.6.0 (for the first v0.6.0 public release) or otherwise
   most recent public stable upgrade, repair, rollback, negative/security
   and two-native-OS acceptance as applicable. Store PASS / FAIL /
   NOT VERIFIED evidence for the exact SHA and signed bytes. A changed
   candidate demands a new review, source identity and complete re-test.
8. **Publish only with separate permission.** Confirm eight-asset identity
   and immutable public release safeguards, perform last-moment drift
   verification, and obtain distinct approval for stage, final publish and
   any production activation. Run postpublication immutable public smoke
   and record exact hashes, source, tag, workflow and host evidence.

## Correctness and trust rules

- **Release-branch lab tests are preliminary.** They cannot certify the
  final signed artifact produced after promotion to `main`. Apply the
  release policy's actual stage gates to their intended phase, not to a
  superficially similar prior SHA.
- **Do not weaken version-specific trust.** The original
  `scripts/draft_release_gate.py` is deliberately pinned to its
  initially reviewed `v0.5.0` test profile. Since v0.5.0 public
  publication was canceled, issue #76 must separately adapt and prove
  the actual v0.6.0 signed-candidate policy before any genuine v0.6.0
  Draft Release is accepted. Future versions similarly need their actual
  prior-public baseline, policy and real signature evidence; a generic
  branch naming convention cannot preapprove them.
- **Hotfixes.** Create a small reviewed hotfix PR directly to `main`
  only when justified and explicitly authorized; then propagate the
  accepted fix to each affected active `integration/*` and
  `release/*` branch through PRs, accounting for already-applied
  patches to avoid duplicates.
- **No implicit protected operations.** Feature implementation,
  documentation, branch creation and test planning are not permission
  to merge into a protected branch, change GitHub rulesets, tag,
  sign, stage, publish, delete historical refs, or activate production.
- **CI is not production proof.** Hosted userspace containers are not
  booted target hosts; synthetic signing keys do not prove true owner
  signing, and a Draft Release is mutable until final publication.
  Follow `docs/RELEASE_ACCEPTANCE_POLICY.md`,
  `docs/SIGNED_CANDIDATE_ACCEPTANCE.md`,
  `docs/DEVELOPMENT_WORKFLOW.md` and original issue criteria.

## Resuming parallel AI sessions

Resume at the last verified approved task, refresh only changed GitHub source/target SHAs, relevant requirements and checks, and avoid repeating the historical bootstrap. Keep issue-, PR-, native-host- and release-level gates separate. A missing requirement blocks its affected operation, not unrelated authorized work.
