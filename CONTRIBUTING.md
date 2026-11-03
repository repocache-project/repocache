# Contributing to REPOCACHE

REPOCACHE is licensed under [Apache License 2.0](LICENSE). Development uses English for code, documentation, reviews, issues, CLI output and releases.

Check existing public issues before proposing changes. File a focused issue with acceptance criteria, compatibility, safety implications and reproduction steps. Keep each PR focused and describe tests actually executed, unverified behavior and operational risks.

## AI-assisted contributions

REPOCACHE uses generative AI extensively in code, documentation and review proposals. Disclose substantive AI assistance in PR descriptions. Do not present an AI-generated review or an unexecuted test as independently verified. The contributor and maintainer remain responsible for license compliance, safe implementation and verifiable acceptance evidence.

## Review and security

The [PR acceptance and review policy](docs/PR_REVIEW_GOVERNANCE.md) defines the effective safety, CI and merge gates. Following the maintainer-directed replacement **once merged into protected `main`**, independent human or AI-assisted technical reviews are optional unless a specific issue or separately binding requirement mandates one. No authenticated original AI-review session URL or external reviewer-provenance artifact is globally required. If a review is used, identify its type accurately; an AI technical opinion is never a formal human GitHub `APPROVED` review. All applicable functional/security acceptance criteria, strict GitHub checks, and **separate explicit maintainer authorization for each merge** remain mandatory; the proposed standing conditional authorization is not active.

- Only Debian 13 and AlmaLinux 10 are currently targeted. Do not assert untested compatibility.
- Preserve APT/DNF failover, rollback, non-interactive CLI output and configuration safety.
- Never add private credentials, internal domain names, operational logs or deployment identifiers.
- For code changes, add appropriate regression, privilege-boundary and failure-path tests.
- Use a feature branch and a PR. **No merge without all relevant criteria PASS, inspected CI outcomes and explicit maintainer approval.**
- Report vulnerabilities privately via [SECURITY.md](SECURITY.md), never through a public issue.
