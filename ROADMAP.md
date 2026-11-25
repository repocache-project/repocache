# Roadmap

GitHub [milestones](https://github.com/repocache-project/repocache/milestones) and original issue acceptance criteria are the live backlog and delivery record. This page summarizes approved release boundaries, not readiness.

| Version | Approved boundary |
| --- | --- |
| v0.4.0 | Published 2026-10-21; existing-NGINX frontend. |
| v0.5.0 | Historical integration work; no intermediate public release. |
| v0.6.0 | Next public release: complete CLI-first caching server on clean Debian 13 and AlmaLinux 10. No v0.4.0 upgrade or legacy migration. |
| v0.7.0 and later | Future work; no new scope or release authorization is implied. |

## Current delivery

**Maintainer decision (2026-11-25):** deliver v0.6.0 first; pause new v0.7.0 feature implementation. Limit active engineering to two streams plus one exceptional auxiliary stream, as described in the [development fast path](docs/DEVELOPMENT_FAST_PATH.md). Preserve all original applicable acceptance and security requirements. Simplify architecture incrementally without implicit contract changes. After v0.6.0, select smaller independently useful releases with explicit maintainer approval of each scope; this does not approve a particular future version, tag or publication.

Use the [approved v0.6.0 target](docs/RELEASE_TARGET_V0.6.0.md), [acceptance stages](docs/ACCEPTANCE_STAGES.md), and [release acceptance policy](docs/RELEASE_ACCEPTANCE_POLICY.md). Finish existing approved work before starting unrelated future features. Preserve original applicable criteria, safe legacy-state refusal, same-version repair, recovery, native acceptance and publisher trust.

Contributors and AI-assisted sessions start with [AGENTS.md](AGENTS.md) and [the development workflow](docs/DEVELOPMENT_WORKFLOW.md). Historical planning remains in [v0.5.0 scope](docs/RELEASE_SCOPE_V0.5.0.md); it is not the current release target.
