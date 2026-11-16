# Native NGINX cache-bypass regression for ENOSPC and read-only storage (Stage A)

**Issue:** #97 (with #28/#29/#31/#24), **release:** v0.6.0.
This CI integration extends the earlier rootless EACCES and synthetic
pressure/hysteresis tests with **kernel-observed ENOSPC on a dedicated
4 MiB Docker tmpfs** and **kernel-observed EROFS on a separate read-only
fixture mount**, using real Debian 13 and AlmaLinux 10 packaged NGINX.

## Containment and expected results

The GitHub Actions job launches an ephemeral Docker container with
`--tmpfs /repocache-ci-enospc:...size=4m`, a read-only checkout bind mount
and an unprivileged UID for the test. A guard refuses root execution,
execution outside Docker, a missing/foreign mount, non-tmpfs mount identity,
a filesystem larger than 8 MiB, insufficient initial free bytes or missing
explicit test intent. Only the dedicated tmpfs may be deliberately filled;
the CI runner's disk, mounted repository and installed NGINX remain untouched.

The scenario:

1. Render genuine project APT/DNF NGINX cache fragments with public pins;
   remap exactly the two fixed upstream endpoints to a private HTTPS fixture
   **after** production source/pin validation. No untrusted redirect or
   public network request is part of the runtime path.
2. Start stock NGINX as an unprivileged disposable process. Demonstrate
   one actual MISS then one HIT for both APT and DNF fixture bytes.
3. Record digests of the warm cache objects. Exhaust only the dedicated
   tmpfs using bounded writes until the **kernel returns ENOSPC**; measure
   remaining free bytes with `statvfs`, without assuming a particular HTTP
   response from an unprotected cache during exhaustion.
4. Feed the real observed critical free-space state to the existing
   **non-authorizing** pressure-to-NGINX candidate logic. Confirm its two
   desired-active repositories use `proxy_cache off`, its own authority
   booleans remain false and stock `nginx -t` accepts the config.
5. Reload **only the disposable test NGINX PID** after syntax validation
   and drain the old worker generation. Prove repeated new APT and DNF
   HTTPS requests return exact fixture bytes from upstream, without HIT
   or new retained cache objects; preserve previously cached byte digests.
6. Remove the synthetic fill file, observe recovered actual free space,
   exercise the existing policy hysteresis and validate/reload the original
   normal cache candidate. Existing APT/DNF warm entries remain HIT without
   new upstream fetch; new entries resume normal MISS/HIT behavior.
7. Exercise a separate read-only cache fixture with ample free bytes and
   inodes. Require the observer to report `ST_RDONLY` and require the kernel
   to refuse a new file with `EROFS`. A full disk or permissions-only refusal
   cannot pass this phase. The decision must report `STORAGE_WRITE_REFUSED`
   and propose cache-off for both routes. Validate and reload only the test
   NGINX process, verify repeated exact upstream bytes without HIT and check
   that the read-only fixture file inventory and digests remain identical.
8. Shut down the private origin and NGINX master; Docker destroys the entire
   temporary filesystem. CI prints fixed PASS/NOT VERIFIED summaries only.

The test fails rather than skipping if dedicated tmpfs identity, the real
ENOSPC or EROFS observation, NGINX validation/reload, worker handoff, byte
integrity, upstream re-fetch, or recovery cannot be demonstrated.

## Acceptance boundaries

**Stage A PASS** requires success of this two-distro native-container
workflow, project regression tests and every applicable exact-head check.
The observed kernel ENOSPC does **not** prove safe automatic installed-host
activation. Neither a cache-off policy proposal nor a test-only NGINX reload
authenticates prior pressure telemetry, the protected #31 generation, root
operator consent, NGINX ownership, native APT/DNF signed metadata, client
source fallback or persistent alert delivery.

**NOT VERIFIED** until the final coordinated #19 campaign: installed
systemd service and enforcing AlmaLinux 10 SELinux, trusted root-controlled
pressure-triggered application, actual signed package/metadata integrity,
native rollback and client upstream fallback. An ENOSPC negative result with
cache **enabled** is not silently treated as successful upstream fallback;
the tested recovery requires an independently authorized, validated cache-off
transition.

## Local reproduction (disposable Docker only)

Run the matching job in
`.github/workflows/server-native-nginx-enospc-bypass.yml` on a disposable
Docker host; never copy the fill routine to a real server or omit the bounded
tmpfs and non-root guards. The workflow installs distro packages only inside
the throwaway image, and the script refuses ordinary host execution.
