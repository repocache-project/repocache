# Native NGINX syntax-valid reload failure and safe rollback (Stage A)

Primary issues: #27 and #31, milestone v0.6.0.

This is a **CI-only** regression for a subtle NGINX behavior: successful
`nginx -t` plus a zero exit status from `nginx -s reload` do **not**
prove the new worker generation has been activated. The native master
performs real listener binding after receiving the reload signal.
If a new port is occupied, the master can refuse the new configuration
while the older workers continue serving the established listener.

## Executed sequence

The dedicated GitHub Actions workflow installs the distribution's stock
NGINX, Python and util-linux in Debian 13 and AlmaLinux 10 disposable
containers. It drops to UID/GID 65534 and requires a Docker marker,
non-root execution, a non-systemd PID 1 and the explicit CI marker.
No host NGINX process, systemd service, protected path or installed
configuration is used.

The script creates a private temporary NGINX prefix, socket listeners
on random loopback high ports and a known healthy response. It then:

1. Starts the real native NGINX master and confirms a healthy HTTP response
   from the baseline listener; captures the actual master worker IDs.
2. Keeps a second loopback socket occupied by the test process. Adds a
   second, syntactically valid `listen` directive to the candidate and
   requires stock `nginx -t` to pass.
3. Sends a real `nginx -s reload` to the private process. Although the
   signalling command exits successfully, the native master eventually
   logs a definite bind refusal. The script waits for that refusal and
   verifies that the original worker generation still serves the original
   route with unchanged content.
4. Restores the exact baseline configuration, runs `nginx -t` and
   sends a second real reload. It waits for the worker generation to change,
   then verifies that the old listener remains healthy and the exact known
   good configuration bytes have been restored.

The script reports fixed PASS/FAIL lines and the explicit NOT VERIFIED
boundaries. Failure to observe an actual bind refusal or actual worker
rollover is a test failure, not a false PASS. Native NGINX keeps the failed
reload log in the temporary test directory; no host logs are printed or
modified. The only network access is isolated loopback traffic.

## Operational consequence

The future privileged #27/#31 server commit engine must distinguish
`nginx -t`, successful reload **signal delivery**, and independently
verified **post-reload live generation and route exposure**. It cannot use
either command exit code as proof of activation or publish an active client
catalog based only on these commands. It must preserve a recoverable
last-known-good configuration and durable transaction journal.

This test supplies repeatable **Stage-A native userspace evidence**.
It does **not** implement that privileged worker, authenticate operator
authority, prove real DNS/TLS, validate a signed installed release,
exercise booted systemd or AlmaLinux SELinux enforcing, or attest
crash-consistent filesystem rollback. Those original issue and #19
release criteria stay NOT VERIFIED until separately executed.
