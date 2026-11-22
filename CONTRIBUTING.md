# Contributing to REPOCACHE

REPOCACHE is licensed under [Apache License 2.0](LICENSE). Development uses English for code, documentation, reviews, issues, CLI output and releases.

Start with the [short development fast path](docs/DEVELOPMENT_FAST_PATH.md) for routine work. Check existing public issues and extend one before creating another; open a new issue only for a genuinely independent deliverable. Keep each PR focused and describe tests actually executed, unverified behaviour and operational risks with links to existing CI evidence instead of duplicated reports.

## AI-assisted contributions

REPOCACHE uses generative AI extensively in code, documentation and review proposals. Disclose substantive AI assistance in PR descriptions. Do not present an AI-generated review or an unexecuted test as independently verified. The contributor and maintainer remain responsible for license compliance, safe implementation and verifiable acceptance evidence.

## Review and security

The [PR acceptance and review policy](docs/PR_REVIEW_GOVERNANCE.md) defines the safety, CI, review and authorization gates. Commissioned independent human review is optional across issues after PR #428; issue-specific substantive security acceptance and GitHub ruleset-mandated approvals remain binding. PR #245 adopted conditional exact-SHA merge permission for qualifying ordinary `integration/vMAJOR.MINOR.PATCH` PRs; it is not a general protected-operations waiver. AI technical assessments are not formal human GitHub approvals. Approved work proceeds through implementation, tests, fixes and PR preparation without redundant intermediate authorizations.

- Only Debian 13 and AlmaLinux 10 are currently targeted. Do not assert untested compatibility.
- Preserve APT/DNF failover, rollback, non-interactive CLI output and configuration safety.
- Never add private credentials, internal domain names, operational logs or deployment identifiers.
- For code changes, add appropriate regression, privilege-boundary and failure-path tests.
- Use a feature branch and a PR. **No merge without every original applicable criterion PASS, inspected required CI and either adopted conditional integration delegation or specific maintainer approval.**
- Report vulnerabilities privately via [SECURITY.md](SECURITY.md), never through a public issue.
