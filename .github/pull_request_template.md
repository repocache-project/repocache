## Summary

Explain the change and the user-facing impact in English.

## Linked Issue and milestone

Identify a primary **same-repository issue** when one exists. For authorized standalone governance/maintenance work, assign an appropriate existing release milestone explicitly instead of inventing an issue. Conflicting issue milestones require maintainer resolution.

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

Follow the [effective PR acceptance and review policy](https://github.com/repocache-project/repocache/blob/main/docs/PR_REVIEW_GOVERNANCE.md) from protected `main`. PR #245 adopted optional global reviews and narrowly delegated qualifying versioned-integration merges; protected exceptions still need specific permission.

- [ ] Every applicable primary-issue/PR acceptance criterion is PASS with reproducible executed or reviewed evidence.
- [ ] Exact PR HEAD, target SHA, ancestry, allowed merge method, issue/milestone routing and all currently required GitHub Actions contexts verified.
- [ ] Security, compatibility, install, upgrade, rollback and documentation impacts evaluated; mandatory FAIL/NOT VERIFIED gates resolved.
- [ ] Independently required issue-specific human/security reviews completed, if any; an optional AI assessment is not a human GitHub approval.
- [ ] Actual submitted human GitHub reviews, unresolved threads, active protection rules and mergeability independently checked.
- [ ] Record either applicable standing conditional integration authority with exact-SHA PASS evidence or separate maintainer approval for this protected operation.

**Applicable acceptance criterion | PASS / FAIL / NOT VERIFIED | evidence:**

**Optional external technical review (if obtained; reviewer type and scope):**

**Actual submitted human GitHub approvals:**

**Tests executed (run IDs/logs); tests not executed:**

**Security findings and remaining native/release/production gates:**

**Merge basis (conditional integration delegation, trusted specific owner decision, or NOT GRANTED):**

## Reviewer notes

List substantive limitations and genuine maintainer decisions. A clean CI status or completed template alone does not authorize merge. Use conditional delegation only for fully accepted ordinary versioned-integration PRs; otherwise require specific permission.
