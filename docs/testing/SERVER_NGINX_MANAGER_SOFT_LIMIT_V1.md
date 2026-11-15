# Actual stock NGINX cache-manager capacity reclamation (issue #97)

Two-distribution Stage-A test: instead of only checking the syntax of
min_free or calculating a cache pressure policy, run the real stock
NGINX cache-manager process as an unprivileged fixture inside throwaway
Debian 13 and AlmaLinux 10 containers.

A private loopback origin serves twenty unique immutable synthetic
64KiB objects. With native max_size set to 16MiB the private NGINX
proxy must return a real repeat cache HIT and retain at least 18
on-disk cache objects. Its private configuration is validated
with nginx -t before the test process itself receives SIGHUP with a
new max_size of 128KiB. The directive min_free=1m is also present
and is separately syntax-checked; it is not used to fabricate low
disk free space. The experiment observes 12 successive one-second
samples and must show at least 50 percent reduction in actual cache
file count and apparent bytes. The test verifies NGINX still serves
new requests afterwards. No opaque cache object is deleted by custom
code.

Native NGINX manager eviction is asynchronous: max_size cannot be
represented as an instantaneous or strict hard quota. This test does
not claim exact eviction order, low-disk ENOSPC, native signed metadata,
installed root-owned cache, systemd service readiness, real SELinux
enforcing, lost-origin fallback or publisher signature acceptance.
All those original #97/#19 host gates remain NOT VERIFIED.

The script refuses root, requires explicit disposable-container opt-in,
and confines every origin, cache, path and NGINX master to a private
temporary folder and network-loopback namespace; no installed service
or third-party NGINX cache is touched. A local rootless Debian NGINX
1.26.3 rehearsal had 21 objects occupying 1.38MB followed by 1
remaining object around 66KiB within the sample interval; CI must
verify the exact committed script on both supported distributions.
