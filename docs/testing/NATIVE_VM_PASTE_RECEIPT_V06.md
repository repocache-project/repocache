# Compact copy/paste receipt for the final v0.6.0 native campaign (#20/#19)

**Purpose:** produce one concise, safe-to-paste line from the existing
read-only candidate identity collector without requiring a file upload.
This is a Stage-A testable formatter, **not** the full native VM runbook,
a signed artifact verifier, or any authority to install, reload or publish.

Only when the complete v0.6.0 source and candidate are ready for the final
snapshot-backed Debian 13 / enforcing AlmaLinux 10 campaign, the operator
may run (from the exact checkout, after independently pinning candidate
and source SHA and verifying issuer signing):

```sh
PYTHONPATH=src python3 -B scripts/collect_native_candidate_evidence.py \
  --candidate /srv/staging/repocache-v0.6.0.tar.gz \
  --sha256 YOUR_VERIFIED_64_CHAR_LOWERCASE_SHA256 \
  --source-sha YOUR_EXACT_40_CHAR_LOWERCASE_SOURCE_SHA | \
  python3 -B scripts/format_native_vm_paste_receipt.py
```

Copy the **one** `REPOCACHE_VM_EVIDENCE_V1=` line into the project
conversation. The formatter reads at most 16 KiB of JSON from standard input,
refuses duplicate keys and contradictory fields, validates exact byte-digest
shapes, and outputs an allowlisted subset. Arbitrary input fields, secrets,
paths, private hostnames and human-entered comments are never forwarded.
Do not paste the raw unredacted VM logs unless requested after review.

All valid results remain `NOT VERIFIED` (or `FAIL` on a mismatched
candidate hash). Exit 2 = partial/pending evidence; exit 1 = detected digest
mismatch; **no successful exit and no release GO are possible**. A matched
candidate digest and read-only systemd observation do not prove publisher
signing, active NGINX, SELinux, actual APT/DNF signed package retrieval,
cache HIT, upstream fallback, root permission boundaries or recovery.

The full #19 campaign still needs separately reviewed per-criterion outputs
and a real booted host; this formatter cannot replace those tests. The
existing user-operated, copy/paste-first workflow must preserve any original
security, publication and native acceptance gates.

CI: `python3 -m pytest -q tests/test_native_vm_paste_receipt_v1.py`.
