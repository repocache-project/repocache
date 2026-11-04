# Supplementary client CI: Markdown-only pull-request pilot

Status: **test evidence in progress — not a policy change**.

This Markdown-only change exists to verify the GitHub Actions event routing
introduced by PR #238, integrated into `integration/v0.6.0` as
`557b7bf1c4ac7097fc52c702c443101b3c5a6f16`.

## Expected pull-request behavior

For a pull request whose **entire effective diff** consists solely of this
`.md` file:

- All **nine mandatory** status checks from `tests.yml`,
  `offline-wheelhouse.yml` and `upgrade-distros.yml` must be created,
  execute on the exact pilot HEAD, and finish successfully. The required
  workflows retain unfiltered `pull_request` triggers.
- The ten supplementary client workflows changed by PR #238 must **not**
  create `pull_request` workflow runs. Their `paths-ignore` patterns exclude
  Markdown files both at the repository root and in subdirectories.
- Any unrelated workflows and manual `workflow_dispatch` events must not be
  mistaken for evidence that the ten client workflows were triggered by this
  pull request. Inspect event type, head SHA and workflow identity together.
- A failure, missing required context, unexpected supplementary run or
  uninspectable routing evidence is **FAIL** or **NOT VERIFIED**, not PASS.

The ten supplementary workflows under test are:

1. `client-atomic-sandbox.yml`
2. `client-entry-approval-plan.yml`
3. `client-entry-candidates.yml`
4. `client-helper-preview.yml`
5. `client-managed-registry.yml`
6. `client-metadata-sandbox.yml`
7. `client-native-fallback.yml`
8. `client-shared-entry-atomic.yml`
9. `client-source-preflight.yml`
10. `client-transaction-metadata.yml`

## Evidence limits and phase-2 boundary

The pilot tests **one real Markdown-only pull_request event**. Static
regression tests from PR #238 cover illustrative code-only and mixed changes;
those are not themselves proof of live GitHub routing for every event shape.
Check the pilot's actual changed-file list, check-runs, workflow-run events and
exact commit before recording the result in its PR.

Phase 2 is a separate design and implementation decision: improving required
CI execution cost must not suppress, rename, skip or weaken any of the nine
mandatory checks. Changes to the three required workflows must be coordinated
with the existing merge-group preparation PRs #239 and #242 and may require
separate security review. No merge-queue activation, rule change, reduced
required-check scope or automatic merging is authorized by this pilot.
