# Private managed metrics rotation candidate (#29)

The closed install-v1 logging opt-in and retention_days setting now drive
a fixed native logrotate configuration for the managed NGINX metrics file.
The current approved log subtree is only /var/log/nginx/repocache-managed;
foreign directories are refused. Opt-out emits no file. Successful opt-in
emits daily numeric rotation, bounded generations (1..3650), lossless rename
rather than copytruncate, delayed gzip, and mode-0600 root-owned re-creation.
The fixed postrotate hook signals the exact nginx.service main PID via
systemctl USR1; it is NEVER executed or installed by this renderer.

CI reuses the generated profile with a private temporary root-only file and
replaces the production service reopen command solely in the disposable
logrotate exercise. It runs real logrotate with forced successive rotations
and confirms retained metrics lines are still parsed by the existing CLI.
This does NOT prove that systemd is PID1 in CI, that a production nginx unit
is vendor-owned, that a live long-running worker reopened safely, that
SELinux labels are correct or that an interrupted logrotate never loses
records. Those remain original #29/#27/#31/#19 gates.

A future signed installer MUST validate installed actual unit and protected
log inode/ownership, preserve existing mandatory audit logs, stage the
profile with recovery, and check NGINX reopen and ongoing log writes.
This Stage-A source has no root authorization or activation entry point.
