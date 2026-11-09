# Contributing to REPOCACHE

REPOCACHE is licensed under [Apache License 2.0](LICENSE). Development uses English for code, documentation, reviews, issues, CLI output and releases.

Check existing public issues before proposing changes. File a focused issue with acceptance criteria, compatibility, safety implications and reproduction steps. Keep each PR focused and describe tests actually executed, unverified behavior and operational risks.

## AI-assisted contributions

REPOCACHE uses generative AI extensively in code, documentation and review proposals. Disclose substantive AI assistance in PR descriptions. Do not present an AI-generated review or an unexecuted test as independently verified. The contributor and maintainer remain responsible for license compliance, safe implementation and verifiable acceptance evidence.

## Review and security

The [PR acceptance and review policy](docs/PR_REVIEW_GOVERNANCE.md) defines the safety, CI, review and authorization gates. The global independent-review/provenance prerequisite has been retired on protected `main`; issue-specific reviews and applicable rulesets remain binding. PR #245 adopted conditional exact-SHA merge permission for qualifying ordinary `integration/vMAJOR.MINOR.PATCH` PRs; it is not a general protected-operations waiver. AI technical assessments are not formal human GitHub approvals. Approved work proceeds through implementation, tests, fixes and PR preparation without redundant intermediate authorizations.

- Only Debian 13 and AlmaLinux 10 are currently targeted. Do not assert untested compatibility.
- Preserve APT/DNF failover, rollback, non-interactive CLI output and configuration safety.
- Never add private credentials, internal domain names, operational logs or deployment identifiers.
- For code changes, add appropriate regression, privilege-boundary and failure-path tests.
- Use a feature branch and a PR. **No merge without every original applicable criterion PASS, inspected required CI and either adopted conditional integration delegation or specific maintainer approval.**
- Report vulnerabilities privately via [SECURITY.md](SECURITY.md), never through a public issue.
