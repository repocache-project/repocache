# #95 — atomic batch repository additions with candidate-only IDs

Supported APT/DNF repositories may be added from validated configuration
alone, with stable generated identifiers when the administrator omits one.
`plan_batch_repository_additions` is a bounded **64-entry pure planner**,
not an installed lifecycle command. It combines explicitly named and
automatic-ID repositories into **one validated candidate** and reports a
per-target add/no-op result. Any invalid, repeated, ambiguous, retired or
conflicting ID or canonical upstream/layout identity refuses the *whole*
batch without yielding a partial candidate.

Generated IDs derive from the strict canonical repository identity and
the caller's all-time reserved ID snapshot, including retired tombstones.
That snapshot is **untrusted** and not a durable reservation. A protected
root-owned state-v2 writer must re-read and authenticate the actual
tombstone set and current generation while holding the #31 lock, reserve
IDs atomically and persist them before any catalog/NGINX activation. Do
not use a generated candidate ID for privileged ownership or external
discovery until this transaction is proven. Duplicate input IDs are not
silently coalesced.

Run `python -m pytest -q tests/test_server_repository_batch_add_v1.py`.
The CI regressions cover two repository types, deterministic auto IDs,
historical tombstone collisions, stable repeated adds, atomic failure,
bad selectors, unallocated input and host I/O denial.

Original #95 AC1/AC2 remain **NOT VERIFIED** for persisted restart/upgrade
and real cache routes (MISS/HIT) on booted Debian 13 and AlmaLinux 10.
An `ADD_CANDIDATE` is never an observed NGINX route, persisted identity
or permission to publish a client discovery catalog.
