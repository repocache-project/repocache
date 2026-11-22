# Exact offline repository proposal review pin (v0.6.0 Stage A)

**Primary issue:** #95. This is a trusted-checkout-only operator safeguard,
not an installed REPOCACHE CLI, authorization token, signed approval or native
NGINX action.

The existing `--dry-run` command in
`scripts/prepare_server_repository_lifecycle.py` calculates the complete
canonical proposed v2 state, auto-generated repository IDs, outcomes and
`proposed_state_sha256`, **without writing a proposal**. When operators
subsequently create the candidate, an optional
`--expected-proposed-state-sha256` condition enforces that the bytes
to be created still match the previously reviewed SHA. This condition is
checked **before** any output/temp file is created. If the reviewed operation,
repository data, decision reference or protected-state predecessor changes
the proposed bytes, the operation refuses without creating a candidate.

Example, after preparing a private 0600 predecessor and request file:

```sh
python scripts/prepare_server_repository_lifecycle.py \
  --previous-v2-state /secure/predecessor-v2.json \
  --request /secure/lifecycle-request.json \
  --expected-generation 1 \
  --expected-state-sha256 "$PREDECESSOR_SHA256" \
  --decision-sha256 "$DECISION_SHA256" \
  --dry-run

# Review the output. Copy its proposed_state_sha256 into REVIEWED_SHA256.
python scripts/prepare_server_repository_lifecycle.py \
  --previous-v2-state /secure/predecessor-v2.json \
  --request /secure/lifecycle-request.json \
  --expected-generation 1 \
  --expected-state-sha256 "$PREDECESSOR_SHA256" \
  --decision-sha256 "$DECISION_SHA256" \
  --expected-proposed-state-sha256 "$REVIEWED_SHA256" \
  --proposal-output /secure/next-v2.json
```

The operator should independently compare the output file SHA-256 with
`$REVIEWED_SHA256` before any separately authorized stage. The output remains
create-only and mode 0600; existing files are never replaced. The existing
no-pin workflow remains available for backward compatibility. Pin syntax is
strictly lowercase 64-character hexadecimal; pin plus `--dry-run` is refused,
as is a pin on a no-op operation. The report field
`review_digest_precondition_checked` records only a byte-digest match, **not**
human review, publisher trust or operator authentication.

The source predecessor is a private caller-selected copy, not proof of the
installed v2 state. Repeated preview/proposal checks cannot eliminate later
host changes or replace the root worker's exclusive-lock predecessor CAS,
original ID/history validation, actual native NGINX route confirmation,
publication/recovery journal, or signed release validation. This enhancement
neither enables cache deletion nor settles retired-identity re-addition
policy.

Regression tests are in
`tests/test_server_offline_lifecycle_proposal_v1.py` on both supported
Python versions, covering exact preview/write correspondence, changed valid
request refusal, existing-file preservation, no-op refusal and malformed pins.
