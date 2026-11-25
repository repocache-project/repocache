# Actual stock NGINX min_free pressure reclamation (issue #97)

This Stage-A two-distro CI test exercises the **min_free** option of the
stock NGINX cache manager, not only its parser syntax. It is distinct
from the independent max_size capacity experiment: max_size remains
16MiB at every step.

A private unprivileged NGINX master, a loopback origin and twenty
immutable synthetic 64KiB objects establish real cache HIT and
more than 18 on-disk cache objects. Native statvfs provides a current
free-space observation. The disposable configuration is changed,
without consuming any host disk space, to a min_free watermark
strictly higher than the available free bytes by at least 15MiB;
then only the private spawned NGINX master receives SIGHUP after
successful nginx -t. The native manager must shrink observed file
count and apparent bytes by over 50% within 12 seconds, while
the private proxy still answers new GET requests. The manager
configuration is subsequently restored with min_free=1m.

This measures one native cache-manager response to a *test-only
threshold*, not real ENOSPC, production free-space policy, a hard
instantaneous limit or signed package integrity. No NGINX opaque
cache bytes are manually removed; all effects are limited to
temporary test-owned files and private loopback. NGINX runs as
UID/GID 65534 on throwaway Debian 13 and AlmaLinux 10 containers.

Original host SELinux enforcing, root-owned installation, TLS,
true disk exhaustion, signed APT/DNF upstream fallback and
booted native systemd recovery remain NOT VERIFIED under #97/#19.

## Independent native inactivity expiry

The same two-distro workflow also runs a separate bounded test of native
inactivity. Two private 8 MiB cache zones each contain one small immutable
object. The idle zone uses a three-second inactivity policy; the independent
control zone uses 600 seconds. Both HTTP freshness periods are 600 seconds.
The test requires real MISS/HIT, allocated bytes strictly below capacity,
no requests while the native manager removes the idle object, preserved
control-zone HIT, and exact response bytes plus origin fetch counts after
repopulation. The timeout is 45 seconds; the measured manager delay is
reported rather than promising expiry at exactly three seconds.
This is an isolated Stage-A runtime observation, not an installed policy
application or booted SELinux acceptance.
