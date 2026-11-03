## Summary

Explain the change and the user-facing impact in English.

## Linked Issue and milestone

Replace `#N` with the primary **same-repository issue** for this PR. If multiple issues belong to different milestones, request maintainer review and assign the PR milestone manually.

Primary issue: #N

Closes #

## Implementation notes

Describe design choices, API/CLI compatibility, and any changes to NGINX, repository sources or stored metrics.

## Verification

- [ ] `PYTHONPATH=src python -m pytest -q` passes.
- [ ] Tested on supported Python versions or documented what could not be tested.
- [ ] Release-bundle/installer tests were run where applicable.
- [ ] English documentation and user-facing text were updated as needed.
- [ ] PR milestone matches the primary issue's planned release (not an acceptance claim).

**Test evidence:**

## Safety and rollout

- [ ] The default behaviour remains read-only/non-destructive, unless explicitly reviewed.
- [ ] No tokens, keys, private hostnames, logs or client identifiers are included.
- [ ] Changes to privileged configuration have a documented rollout and rollback plan, if applicable.
- [ ] Existing stable commands/JSON consumers remain compatible, or migrations are described.

**Deployment plan:**

**Rollback plan:**

## Acceptance and protected merge (required)

Follow the [PR acceptance and review policy](https://github.com/teixemf/repocache/blob/main/docs/PR_REVIEW_GOVERNANCE.md) from the **currently protected default branch**. The optional-review change is effective only when its policy amendment is merged.

- [ ] Every applicable primary-issue/PR acceptance criterion is PASS with reproducible executed or reviewed evidence.
- [ ] Exact PR HEAD, target SHA, ancestry, allowed merge method, issue/milestone routing and all currently required GitHub Actions contexts verified.
- [ ] Security, compatibility, install, upgrade, rollback and documentation impacts evaluated; mandatory FAIL/NOT VERIFIED gates resolved.
- [ ] Independently required issue-specific human/security reviews completed, if any; an optional AI assessment is not a human GitHub approval.
- [ ] Actual submitted human GitHub reviews, unresolved threads, active protection rules and mergeability independently checked.
- [ ] Separate explicit maintainer authorization for **this PR and evaluated HEAD** recorded before merge.

**Applicable acceptance criterion | PASS / FAIL / NOT VERIFIED | evidence:**

**Optional external technical review (if obtained; reviewer type and scope):**

**Actual submitted human GitHub approvals:**

**Tests executed (run IDs/logs); tests not executed:**

**Security findings and remaining native/release/production gates:**

**Explicit merge permission (trusted owner decision, or NOT GRANTED):**

## Reviewer notes

List limitations, follow-up issues and maintainer decisions. A clean CI status or completed template does not authorize merge. Standing conditional authorization is not active; obtain explicit PR-specific maintainer merge permission.
