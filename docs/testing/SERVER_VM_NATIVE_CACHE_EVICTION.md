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
