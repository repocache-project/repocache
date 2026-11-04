# Required CI PR supersession — phase 2 (v0.6.0)

This applies only to the three mandatory CI workflows in the v0.6.0
integration lane. It does not change any of the nine required status names,
matrices, unfiltered pull_request/push/merge_group triggers, read-only
permissions, pinned actions or release gates.

For initial pull_request attempts, concurrency is grouped by workflow and PR
number. A new revision can cancel the previous run for the same PR, without
interfering with another PR or another required workflow. A cancelled old-HEAD
check is NEVER PASS and cannot substitute for current-HEAD success.

Manual retries (run_attempt greater than one) are isolated using event, SHA
and run ID, with cancellation disabled. Protected pushes, merge groups and
manual workflow_dispatch runs use the same isolated, never-cancel policy.
This does not enqueue, merge, sign, publish or change any GitHub ruleset.

CAVEAT: GitHub's concurrency scheduler does not guarantee FIFO ordering.
A delayed old initial PR webhook could still displace a newer one. Never
trust concurrency as an authorization or current-HEAD oracle. All nine
required checks must be completed/success on the current exact revision
before a merge, and the current target base must also be reverified.

Evidence: the source/mutation tests verify declared policies and scenarios,
not GitHub cancellation behavior. A two-revision live pilot is required to
show cancellation of obsolete jobs and success on the latest HEAD. Compare
runner job timestamps before and after to establish measurable savings;
the existing one-PR docs-only baseline is not a statistical trend.
These operational and efficiency criteria are NOT VERIFIED until piloted.

Any forward-port to protected main, v0.7.0 or future lanes requires a separate
review of the source and exact-HEAD CI. Rollback must use an ordinary reviewed
revert PR, not direct changes to protected branches or bypass of required CI.

## Live pilot setup

A follow-up documentation-only commit on the same open PR is used to check
whether a new pull_request revision supersedes the preceding required-CI
workflow runs. Both revisions have the same reviewed concurrency expressions.
This marker is not itself acceptance evidence; use the actual GitHub run
conclusions and current exact-HEAD check statuses for PASS/FAIL decisions.
