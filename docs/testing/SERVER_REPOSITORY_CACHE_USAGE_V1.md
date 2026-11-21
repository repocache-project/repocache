# Read-only selected-repository NGINX cache usage (#29/#97/#95)

A cache directory being named in a requested installation document is **not**
evidence that it belongs to REPOCACHE or that it can be deleted. This Stage-A
observation reuses the existing descriptor-pinned cleanup preflight, which
checks the fixture's trusted root-owned cache/repository marker and the strict
NGINX levels=1:2 on-disk object layout. The API does not open arbitrary paths,
follow symlinks, inspect bytes or invoke external commands.

The function `preview_owned_repository_cache_usage_under_root` accepts a
nonempty ordered tuple of up to 500 *caller-selected* valid repository IDs and
explicit detached test-root descriptor/owner IDs. It sorts IDs, rejects
duplicates, and refuses **the entire report** if any selected repository is
missing, foreign, malformed, changed or cannot be observed. A maximum of
100,000 scanned cache objects/directories across the selection and 64-bit
bounded totals prevent uncontrolled aggregation. Per-repository and selected
total counts include regular files, levels directories, logical byte sizes,
and allocated data blocks from actual file metadata. They never include
unobserved or omitted repositories.

This is an **observed selected subset**, not a complete inventory. It
explicitly reports `full_cache_inventory_verified=false`,
`all_repository_ids_authenticated=false` and
`multi_repository_snapshot_atomic=false`: independent read-only scans
cannot provide a shared transaction snapshot while NGINX is active.
Allocated blocks are not guaranteed reclaimable disk space (filesystem
semantics, quotas, cache ownership and active transfers can differ). A
zero-byte selected subset is never an assertion of zero overall cache use.

GitHub Actions runs real Linux descriptor, marker, file-size, missing/foreign
repository, unsafe layout, invalid selector and no-host-mutation tests as an
unprivileged user in Debian 13 and AlmaLinux 10 containers. This is genuine
CI-level implementation evidence **only**, and does not prove an installed,
authenticated root-owned cache inventory, systemd/SELinux enforcing, trusted
metrics, a complete disk pressure alarm, safe selective deletion, native
NGINX quiescence or live operator-approved cleanup. Original #29/#95/#97/#19
acceptance remains NOT VERIFIED where those conditions apply.

## Locked all-time v2 repository cache attribution (fixture only)

The new `preview_locked_v2_repository_cache_usage_under_root` joins the
actual canonical protected v2 ID/reservation history and its committed
generation/hash with the read-only marked native cache observations under
one exclusive detached-fixture state lock. Unlike the older caller-selected
subset, it **does not accept a caller-supplied list of IDs**. It reports
allocated and permanently retired IDs, desired active/disabled/removed
state, whether each exact marked cache root exists, and its individually
verified file/directory/logical/allocated byte counts.

It scans the fixed managed cache namespace and the root-owned repository
marker names for unknown or unmarked directories, refusing partial reports
on foreign paths, symlinks, ownership drift, pending WAL, invalid manifests,
stale whole-state SHA or missing active repository roots. A disabled or
retired repository that never acquired storage may have an explicit zero
row. Counts from 500 or fewer historical IDs are bounded; if historical
volume exceeds that supported scope the whole report is refused.

This is **not an atomic snapshot of active NGINX cache workers**: their
files can grow between sequential scans, and verified allocated blocks are
not proof of reclaimable space. Protected fixture state, not an installed
root administrator identity, provides the list; all host/SELinux/security/
cleanup/publication permissions remain false. No cache or v2 state is
modified and no public CLI or second allowlist is introduced.

```sh
python -m pytest -q tests/test_server_repository_cache_usage_v1.py
```

Tests cover retained retired APT bytes, a concurrently configured DNF
repository's bytes, unobserved disabled roots, active-but-missing root
refusal, foreign directories/owner markers/symlinks and pending or stale
protected state. The full #95 operational acceptance remains open.
