# Batch repository removal intent — inert Stage A (#95)

The frozen administrator CLI contract includes \`repocache repos remove
[ID...]\`, \`--all\`, default cache retention, and idempotent removal of an
already-absent ID. Batch operations must reject contradictory global
selectors before mutating resources.

The new pure \`plan_batch_repository_removals\` builds a **single validated**
candidate document from a complete ID-bearing v1 snapshot. It returns
per-target \`REMOVE_CANDIDATE\` / \`ALREADY_ABSENT\` classifications and an
explicit proposed retired-ID list, preserving caller order for explicit
targets and deterministic ordering for \`--all\`. Cache is **always retained**;
the planner has **no purge parameter** and does not access files, network,
package managers, NGINX, root control, public catalog or persistent state.

The required all-time retired-ID/tombstone ledger, authenticated operator,
actual current generation and #31 journaled NGINX+catalog withdrawal still
belong to the privileged writer, not this caller-supplied snapshot. The
planner does not grant retirement, cache deletion, service reload, catalog
publication or data mutation. The currently installed CLI is unchanged.

Stage A covers complete plan and adversarial regression cases. A future
production \`repos remove\` requires the canonical CLI integration, protected
live state, authorization, active-only route/catalog withdrawal, safe
same-version retry and dual-distribution booted #19 validation.
