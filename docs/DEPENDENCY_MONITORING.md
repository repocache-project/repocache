# Dependency monitoring and review policy

**Status:** initial v0.5.0 monitoring proposal for [#81](https://github.com/teixemf/repocache/issues/81), tracked by [#79](https://github.com/teixemf/repocache/issues/79). This does **not** change the immutable v0.4.0 release, enable online dependency installation, or close the full #81 acceptance gate.

## Scope and authority

- REPOCACHE retains its Typer/Rich command-line interface and Textual TUI. The v0.4.0 signed release installs its own audited, immutable offline dependency wheelhouse. **Do not** change its files, signatures or acceptance record.
- `.github/dependabot.yml` monitors Python packaging under `/`, reviewed monitoring-only pip manifests under `/deps`, and SHA-pinned GitHub Actions in `.github/workflows` weekly on default branch `main`. The `/deps` manifests do not change installer or release lock inputs.
- Dependabot version-update PRs are **proposals**, not authorization to upgrade released installations. Reviewers must not enable auto-merge. Do not install unreviewed latest upstream releases in production.
- Existing `pyproject.toml` declares version **ranges** for Typer/Rich/Textual. The custom `deps/runtime-wheels.lock` and `deps/build-wheels.lock` pin actual v0.4.0 wheels/hashes but are **not guaranteed to be ingested** by GitHub's dependency graph or Dependabot. Neither Dependabot's recognition of the PEP 621 `pyproject.toml` nor the presence of this config proves detection of the exact runtime and transitive packages. A recognized, complete lock for both supported Python targets is designed under [#80](https://github.com/teixemf/repocache/issues/80) and implemented/reconciled before claiming #81 complete.
- For initial Python version updates, `increase-if-necessary` avoids casually rewriting existing broad version bounds. It may produce **no** update PR when a new stable version already satisfies the current constraints. This is not a substitute for monitoring an exact signed release dependency lock.
- Existing branch protections, reviewer approval, pinned action SHAs, CI, owner-only offline Ed25519 signing and publication gates still apply.

## One-time maintainer verification

In **Settings > Security & analysis** (the wording may vary), independently inspect/enable:
1. Dependency graph.
2. Dependabot alerts.
3. Dependabot security updates.
4. Notifications for vulnerability/security alerts in repository and account notification settings.

Dependabot **version** updates become active only after the reviewed `.github/dependabot.yml` is merged into the default branch. Alerts/security updates are not enabled by that YAML alone. The GitHub connector used for this initial implementation does not expose reliable read/write APIs for these effective settings; record operator-side evidence in #81, not an invented PASS.

After the config is merged, inspect **Insights > Dependency graph**, **Security > Dependabot alerts**, and the **Dependabot** update jobs/logs on the repository's GitHub UI. Record which direct/transitive packages, resolved versions, and supported Python profiles actually appear. Save a sanitized job URL or PR proving that each ecosystem's update check executed. Never introduce a deliberately vulnerable live dependency solely to demonstrate alerting; a controlled fixture in a nonproduction test repository or verified historical public advisory can be used if the workflow permits.

## Reviewing new versions / security alerts

1. For alerts: record advisory reference, affected installed/declared versions and available fixes. Distinguish vulnerable released wheelhouse versions from future source-only installs. Prioritize exploitable or remotely reachable exposure and high-severity advisories; if no safe fixed release exists, document mitigations and deployment guidance.
2. For version PRs: inspect origin, release notes, removed or added transitives, license notices, Python ABI/platform support, wheel availability, package provenance, suspicious ownership or dependency changes, API/CLI/TUI compatibility and security impact.
3. Verify every direct/transitive/build dependency from a complete release-specific lock under the supported Python interpreters: Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12. Changes to signed lock entries/hashes and dependency policy require explicit owner review; **never automatically replace a v0.4.0 pinned wheelhouse**.
4. Run exact-head CI, full CLI/JSON/exit-code/TUI regressions, native installation and transactional rollback tests, offline legacy release tests and, after #83/#84, online hash-pinned download plus outage/compromised-index negative tests. Tests must check results, not merely existence. Block merge on any required FAIL or NOT VERIFIED.
5. Before merging review branch head, reviews, checks, protected branch rules and all issue acceptance criteria. Require explicit maintainer approval. Merge is **not** a release: prepare an independently signed release candidate, execute the [#76](https://github.com/teixemf/repocache/issues/76) acceptance gate, then separately authorize signing and publication.
6. Publish emergency security maintenance releases through the same authenticated process. Do not hot-swap Python wheels inside immutable previously published assets or silently upgrade user installations.

### Interaction with #74

[#74](https://github.com/teixemf/repocache/issues/74) exclusively tracks GitHub Actions migration to reviewed Node.js 24-native releases. Dependabot PRs updating `actions/checkout`, `actions/setup-python`, or `actions/upload-artifact` **must not bypass** that issue's full-SHA, artifact-upload, credential-scope or nine required status-check criteria. If both the maintainer and Dependabot propose the same change, select one reviewed PR and close the redundant one after verifying exact SHA; do not merge both blindly.

## Planned additional coverage (NOT VERIFIED)

- Release-recognized direct/transitive/build dependency locks accepted by Dependabot for both supported target interpreters, or a least-privilege GitHub dependency submission strategy if static graph ingestion is incomplete (#80/#81).
- Evidence that security alerts and security-update PRs work using a safe controlled advisory example (not tested yet).
- Evidence that actual weekly checks produce actionable Python and Actions version-update PRs (not tested yet).
- A future wheelhouse-free, online-hash-locked source-only release profile (#82–#85).

## Acceptance status (initial PR)

| Criterion | Status | Evidence |
| --- | --- | --- |
| Version-update config authored for pip and Actions | PARTIAL | `.github/dependabot.yml` in draft PR; syntax/local validation to be recorded |
| Live Dependabot jobs / update PRs | NOT VERIFIED | Requires config on `main` and actual GitHub runs |
| Alerts / security-update repo settings enabled | NOT VERIFIED | Operator must inspect GitHub settings |
| Resolved direct + transitive vulnerability graph | NOT VERIFIED | Existing custom release wheel locks are not a verified supported manifest |
| Safe controlled security-alert test | NOT VERIFIED | Not executed |
| No auto-merge / Actions release authority | PARTIAL | No auto-merge configured; requires branch-policy and live-PR verification |
| Required CI / exact-head reviews / owner approval | NOT VERIFIED | Inspect after PR checks; no merge approved |

## 2026-10-25 checkpoint: legacy inventory guard and remaining owner gates

The historical "initial PR" table above records the first proposal, not the
current default-branch result. [PR #87](https://github.com/teixemf/repocache/pull/87)
has since merged, and [issue #81](https://github.com/teixemf/repocache/issues/81)
records successful **real** GitHub Dependabot pip and Actions update jobs.
These are update-job observations, **not** proof of vulnerability-alert coverage.

As of merged [PR #200](https://github.com/teixemf/repocache/pull/200),
Dependabot also monitors three exact-hash, **monitoring-only** manifests:
`deps/requirements-debian13-py313.txt`,
`deps/requirements-almalinux10-py312.txt`, and
`deps/requirements-build-v05.txt`. These mirror the reviewed legacy
runtime/build lock tuples, with source-parity regression coverage in
`tests/test_dependency_graph_manifests_v05.py`. They are **not** release
installer inputs, a resolved dependency graph, or evidence that GitHub
actually ingested all direct and transitive packages. Confirm effective
GitHub ingestion, alert configuration, and the safe advisory test separately
before accepting parent issue #81.

The read-only regression in `tests/test_dependency_inventory_v05.py`
checks the current **legacy** source-controlled inventory without changing
release assets or the signed lock format:

- 12 exactly named and SHA-256-pinned runtime distributions, including all
  three directly declared PEP 621 requirements (Typer, Rich, Textual);
- 2 separately pinned build distributions (setuptools and wheel), with the
  declared build backend represented;
- normalized-name uniqueness, strict legacy record syntax, and hostile /
  ambiguous record refusal. Any added or removed legacy package requires
  review and an explicit inventory-test update.

Reproduce this scoped check with
`python -m pytest -q tests/test_dependency_inventory_v05.py`.
An executed test result is evidence of **source-level lock consistency only**.
It cannot prove current PyPI wheel hashes, complete transitive metadata,
cross-platform resolutions, or GitHub dependency-graph ingestion. Existing
native wheelhouse CI separately executes `pip check` and compares installed
wheel versions, but it also does not prove GitHub ingested those distributions.

**Still NOT VERIFIED / blocking #81 closure:**

1. Maintainer-recorded effective GitHub Dependency Graph, Dependabot Alerts,
   Dependabot Security Updates and alert-notification settings. Record actual
   Settings / Insights / Security UI evidence, not merely YAML presence.
2. Complete observed GitHub direct **and transitive** graph for each approved
   Debian 13 / Python 3.13 and AlmaLinux 10 / Python 3.12 runtime **and build**
   lock profile, tied to reviewed exact distribution names, versions and hashes.
   The legacy `deps/*.lock` files are not Dependabot-recognized pip
   requirement manifests, and `pyproject.toml` supplies ranges, not pins.
   Do not silently generate unreviewed OS-target pins from the legacy locks.
3. A controlled, nonproduction vulnerability advisory/alert and remediation
   workflow test, with evidence of any proposed security-update PR.
4. Independent review of any future static manifest or dependency-submission
   integration, especially token permissions, trusted push-only execution and
   no release/signing access. Keep #74 action-pin approvals independent.
5. Final criterion-by-criterion exact-head CI, reviewer and maintainer
   acceptance before closing the parent. No unsigned or test-only artifact
   may be described as a published signed release.

**Owner action:** Inspect GitHub Settings > Security & analysis, Insights >
Dependency graph, Security > Dependabot alerts and account/repository
notifications. Record a sanitized evidence link or dated observation for all
four effective settings and one safe advisory workflow; do not post any
credential or security token. If GitHub cannot recognize the complete
per-platform locks, explicitly retain NOT VERIFIED and design a separately
reviewed trusted-commit dependency-submission workflow rather than granting
write rights to untrusted PR code.

## v0.5.0 read-only resolved dependency graph preview (#81)

The GitHub Dependency Graph recognized all 26 monitoring-only pinned package rows
(12 runtime rows for each target and 2 shared build rows), but the owner-
exported SPDX for merged PR #200 reported **zero Python package-to-package
edges**: every pinned package appeared as directly required by REPOCACHE.
Static exact-hash pins do **not** prove transitive relationships or correct
build-vs-runtime scopes. This remains a **blocking #81 acceptance gap**.

The proposed CI-only `scripts/ci_dependency_graph_v05.py` reads the **actual
SHA-256-verified upstream wheel METADATA** in the two existing native
Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12 container environments.
It compares each distribution's name, version and bytes against the reviewed
legacy locks, applies target Python environment markers and requested extras,
and constructs only the edges declared by the verified wheel metadata. Every
active unpinned, out-of-lock or incompatible dependency is a hard failure;
unreachable locked packages are also refused. The separately approved
`setuptools` and `wheel` build tools appear in the proposed snapshot with
`development` scope, never as application runtime dependencies.

**Safety boundary:** this is a **read-only graph preview** written into a
throwaway container's private workspace. It never sends a dependency snapshot
to GitHub, never uses the API token, never modifies the signed legacy wheel
locks or installer, and never activates online installation. PR CI has
`contents: read` only. The native-image CI validates user-space metadata,
not booted target kernels, systemd, SELinux or release publication.

GitHub prioritizes user-submitted dependency snapshots above its own Python
Dependabot graph jobs and static parsing. Publishing these previews therefore
requires a **separately reviewed, strictly main-only and least-permissioned**
submission implementation (the official API currently requires the job's
`contents: write` privilege). Its isolation, correct profile-specific
correlators, anti-PR-token boundary and observed GitHub post-integration
rendering must pass review **before any merge that grants write permission**.
This preview PR alone **does not** satisfy #81's production graph acceptance.
Do not infer that successful native wheel metadata validation is evidence of
real alert notification delivery or the owner-signed release candidate.

### Proposed restricted submission stage (Draft PR #206; not active until reviewed merge)

In the proposed `.github/workflows/dependency-graph-submit-v05.yml`:

- A **read-only** matrix resolves reviewed SHA-256 wheel identities for Python
  3.13 and 3.12 on disposable GitHub-hosted Linux runners. Wheel package
  code is not installed or executed; output is a same-run ephemeral artifact.
- Only a separate job triggered by `push` on protected `main` receives
  `contents: write`. PR compute jobs retain `contents: read` and
  `persist-credentials: false`; no `pull_request_target` or `workflow_run`.
- The publisher compares the complete **canonical per-parent adjacency**
  against source-controlled, independently reviewed v0.5.0 wheel metadata,
  not merely a total of 14 edges. Native Debian and AlmaLinux validation
  and hosted producers must match this exact same adjacency contract.
- The **read-only preflight** independently validates source locks, monitor
  hashes, build/runtime scopes and exact manifest/edge identities. It emits a
  size-bounded, base64-encoded complete three-manifest payload via a GitHub
  Actions job output; the value contains data only, never code or credentials.
- The separate **write-scoped publisher executes no third-party Actions**
  (`uses:`), no checkout, no artifact downloads, no package installation and
  no source-controlled Python. Its one inline, standard-library-only Python
  step validates the output's SHA, source branch, detector, manifest inventory
  and scopes; checks live protected `main`; then submits one atomic snapshot.
  It requires HTTP 201 plus an explicit `result: SUCCESS`, forbids proxies
  and redirects and never logs its token.
- GitHub-hosted runner and reviewed inline workflow source remain part of the
  privileged trusted computing base. This removes the former F-03 exposure
  **to checkout/download Actions in the write job**, but does not imply an
  invulnerable runner, immutable workflow code or zero token risk. The
  preflight-to-publisher job output is a trusted same-run data boundary; its
  non-production PR evaluation and post-merge API submission require evidence.
- The three reviewed source manifests remain separate GitHub graph entries:
  `deps/requirements-debian13-py313.txt`,
  `deps/requirements-almalinux10-py312.txt` and
  `deps/requirements-build-v05.txt`, with build helpers in `development`
  scope. GitHub prioritizes user submissions over Dependabot graph jobs,
  so independently verifying its rendered results is mandatory.
- Snapshot collection uses hosted Linux Python 3.12/3.13, not native distro
  userspace. The separate exact-SHA Debian 13 and AlmaLinux 10 native
  jobs still validate the same SHA-256-verified wheel bytes and metadata.
  None of these CI jobs proves booted SELinux/systemd or release signing.

**Status: proposed, unmerged.** Draft PR #206 has not been independently
security-reviewed or accepted for merge. The protected-main post-merge
submission, real Dependency Graph labels, SBOM relationships, security
notifications and owner acceptance remain NOT VERIFIED. No signed wheelhouse,
installer, production service or publication permission changes are implied.

The isolated private lab separately demonstrated 11 real alerts and a
security-update PR; it does not prove production graph completeness or
personal notification receipt.

### Incorrect accepted graph: containment, recovery and evidence

A successful HTTP 201 and `result: SUCCESS` do not prove that GitHub displayed
the correct graph. Manual submissions can take precedence over GitHub's
automatically discovered dependencies. An inaccurate graph blocks #81.

1. **Contain:** Stop further graph publication by a separately authorized,
   reviewed protected-main workflow change. Keep #81 open and do not approve
   automated dependency PRs on the basis of the disputed graph. Disabling
   the workflow does **not** remove an already accepted snapshot.
2. **Preserve:** Record the offending snapshot JSON, exact source SHA, source
   locks, CI/workflow run, API result, GitHub Dependency Graph and SPDX
   screenshots. The stable detector is `repocache-verified-wheel-metadata`
   and the combined correlator is `repocache-v05-wheelmeta-two-target`.
   Never disclose or archive an API token.
3. **Correct:** Regenerate all three manifests from exact source-locked
   SHA-256-verified wheels; independently validate every parent-to-child
   relationship, all marker conditions, runtime/build scopes and both
   native Debian13/Python3.13 and AlmaLinux10/Python3.12 environments.
   Run the adversarial in-lock edge-substitution regression and the actual
   two-artifact unprivileged preflight before any renewed submission.
4. **Review and authorize:** Obtain a new independent exact-HEAD review,
   explicit maintainer acceptance of any residual risk and a separate
   merge authorization. Only an authorized protected-main push may submit
   a corrected, complete three-manifest snapshot using the same stable
   detector/correlator. Require HTTP 201 and `result: SUCCESS`.
5. **Read back:** Confirm the submitted SHA, both sets of 12 runtime
   entries, all 14 **actual** edges per runtime profile, both build helpers
   in `development` scope, direct/indirect labels, fresh SPDX output and
   corresponding alert behavior. The HTTP result alone is insufficient.
6. **Escalate on failure:** Leave #81 blocked and the publisher stopped;
   contact GitHub Support with sanitized exact SHA, detector/correlator,
   response, expected inventory and incorrect graph readback. A workflow
   revert cannot be assumed to delete or restore a graph snapshot.

The pre-POST check of current main and the POST are separate HTTP requests:
main can advance between them (TOCTOU). After any authorized submission,
compare the returned snapshot SHA and current protected-main revision;
an obsolete snapshot requires a fresh reviewed main submission.
Neither the combined API POST nor its expected status proves atomic
GitHub UI rendering or automatic recovery.

The resolver currently imports `pip._vendor.packaging`, a private pip API.
The tested Python 3.12/3.13 implementations work, but a future pip change
must fail closed, be independently assessed and never silently change
source-controlled adjacency relationships.

### Always-present native and graph security check candidates (Draft PR #206)

The unfiltered `.github/workflows/tests.yml` proposes two stable checks:
`Native Dependency Security Gate` and `Dependency Graph Security Gate`.
They run for every PR targeting protected `main` and each `main` push,
regardless of changed-file paths. On other ref families (including immutable
legacy release branches) the check jobs still exist and explicitly report
not applicable; no old-release dependency lock/profile is silently asserted
compatible.

The native gate invokes the existing **read-only reusable** native workflow
and fails if either Debian13/Python3.13 or AlmaLinux10/Python3.12 matrix job
is failed, cancelled or skipped. The graph gate separately collects the two
source-hash-matched PyPI wheel metadata artifacts without import/installation,
requires success for the complete producer matrix, downloads only same-run
artifacts and executes the existing independent stdlib preflight. Its result
is FAIL for absent, failed, skipped, malformed or incomplete evidence.

Both final gate jobs use `if: always()` and explicitly reject anything
other than upstream `success`, preventing a failed prerequisite from causing
a misleading skipped gate. All jobs use `contents: read`, full-SHA-pinned
official Actions and `persist-credentials: false`. Neither gate can invoke
the write-scoped graph publisher, which remains solely in the separate
protected-main-only workflow and **is NOT run by these tests**.

**Governance limit:** merely introducing these two CI checks does not alter
the effective protected-main ruleset. Before they become mandatory merging
checks, separately authorize a ruleset update referencing the exact stable
check names and GitHub Actions integration ID, after independent review and
actual CI demonstration that both checks always appear and fail closed.
Do not add the old path-filtered workflow jobs as required contexts. Never
treat current successful read-only gates as proof of a real dependency API
publication, GitHub graph readback, owner notification or signed release.
