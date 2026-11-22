## Change

Primary issue: #N
Target milestone / branch:
**What changed and why?** (2–4 sentences)
Substantive AI assistance, if any:

## Evidence

- Exact PR HEAD / target base:
- Relevant acceptance criteria: PASS / FAIL / NOT VERIFIED, with CI/test links (link the existing issue checklist; list only changed or exceptional results):
- Tests executed beyond required CI, or tests not executed:
- Native VM / signed-candidate / broader parent-issue criteria still open (if applicable):

## Risk and recovery

- Risk: low (docs/test), normal (feature/fix), or high (privileged install, TLS, APT/DNF, signing, recovery, trust boundary).
- Security/compatibility effect; negative tests if relevant:
- Rollback / refusal / recovery behaviour if applicable:

## Integration

- Required checks and blocking threads: inspect on the **exact** HEAD/base immediately before merge.
- Authority: PR #245 standing conditional **versioned-integration** delegation only if all applicable gates PASS; otherwise separate explicit maintainer approval. No automatic main/release merge or publication authority.
- Link: [staged acceptance](../docs/ACCEPTANCE_STAGES.md) and [default fast path](../docs/DEVELOPMENT_FAST_PATH.md).

The issue checklist is the full acceptance ledger. Do not paste duplicated CI logs or omit a required criterion. A green CI run does not establish native-host, signing or release acceptance.
