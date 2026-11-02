# Contributing to REPOCACHE

REPOCACHE is licensed under [Apache License 2.0](LICENSE). Development uses English for code, documentation, reviews, issues, CLI output and releases.

Check existing public issues before proposing changes. File a focused issue with acceptance criteria, compatibility, safety implications and reproduction steps. Keep each PR focused and describe tests actually executed, unverified behavior and operational risks.

## AI-assisted contributions

REPOCACHE uses generative AI extensively in code, documentation and review proposals. Disclose substantive AI assistance in PR descriptions. Do not present an AI-generated review or an unexecuted test as independently verified. The contributor and maintainer remain responsible for license compliance, safe implementation and verifiable acceptance evidence.

## Review and security

The [PR review and acceptance policy](docs/PR_REVIEW_GOVERNANCE.md) defines the maintainer-approved Option B governance model: substantive independent technical evidence is required for every PR and exact HEAD. Under the proposed per-report simplification, a separately commissioned, evidence-backed technical second opinion with an unblocked PASS would not require an additional owner sign-off **after that amendment is adopted**. It still cannot replace an eligible human GitHub `APPROVED` review where such review is independently mandatory, waive acceptance/security requirements or authorize merging. The proposed **standing conditional merge authorization** in the same policy is **not active**: individual explicit maintainer merge approval remains mandatory until a separately authenticated and valid activation under approved governance. The GitHub rulesets require strict checks but zero formal approving reviews; maintainers must enforce all independent project acceptance gates, not just CI.

- Only Debian 13 and AlmaLinux 10 are currently targeted. Do not assert untested compatibility.
- Preserve APT/DNF failover, rollback, non-interactive CLI output and configuration safety.
- Never add private credentials, internal domain names, operational logs or deployment identifiers.
- For code changes, add appropriate regression, privilege-boundary and failure-path tests.
- Use a feature branch and a PR. **No merge without all relevant criteria PASS, inspected CI outcomes and explicit maintainer approval.**
- Report vulnerabilities privately via [SECURITY.md](SECURITY.md), never through a public issue.
