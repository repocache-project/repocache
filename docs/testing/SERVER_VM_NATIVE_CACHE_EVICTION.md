# Native VM capacity eviction — #97

The existing PR #237 smoke guest now runs a bounded, non-root native NGINX
capacity experiment after its TLS APT/DNF smoke. It starts a separate private
loopback origin and proxy and validates syntax before startup. Twelve
128 KiB synthetic objects compete in a 512 KiB native cache zone, with a
separate 8 MiB control zone. Both use 600 s inactivity and freshness. The
probe waits at most 90 s for measured allocated bytes to settle within the
capacity limit, then requires a previously observed HIT to become a MISS
with identical bytes and a new origin fetch. The independent zone must
remain HIT without a repeat origin fetch. The elapsed time must be less
than inactivity, so nominal inactivity cannot explain eviction.

No actual disk exhaustion, installed NGINX, client changes, publisher
signatures, managed filesystem contexts or policy activation are tested
by this capacity probe. No opaque cache object is manually deleted; only
the disposable directory is cleaned after its private master stops.
The finite workload writes less than a few MiB, not a fill of guest or
runner storage. Native max_size is a soft asynchronous target, not a hard
instantaneous quota. This is baseline #97 evidence only, not a reopening
of #94 or an advanced eviction engine.

Evidence: inspect the smoke job's native-cache-data-plane.txt and exact
source SHA for each distro. A passing local/container run is not booted
VM evidence. The original installed #97 acceptance criteria remain open
until tested in the appropriate assembled environment.

## Real ENOSPC and EROFS in a booted guest

The same smoke guest also reuses the existing container ENOSPC/EROFS scenario
through a separate root wrapper. The wrapper verifies x86_64 QEMU/KVM,
systemd, exact target, inactive packaged service and private mount namespace
with no shared propagation. It creates two 4 MiB tmpfs mounts in a unique
root-owned temporary directory, remounts one read-only, and runs the actual
workload as pr237ci. Capacity, mount type and read-only state are checked
before use. The fill is bounded to the writable tmpfs; both mounts are
unmounted on exit. No runner storage exhaustion or external cache deletion.

The common scenario now observes actual free inode counters and verifies a
real successful write after releasing the fill before proposing restoration.
It checks genuine ENOSPC and EROFS, staged stock nginx syntax, private worker
reload and drain, upstream fixture bytes during bypass, preserved cache
hashes, hysteresis and MISS/HIT recovery. This is an isolated workload, not
proof of an installed privileged automatic pressure trigger or signed client
fallback. Production SELinux cache/log contexts remain unverified.
