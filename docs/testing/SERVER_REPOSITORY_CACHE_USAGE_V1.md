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
