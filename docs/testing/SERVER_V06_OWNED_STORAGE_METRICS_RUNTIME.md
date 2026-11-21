# Owned storage and metrics runtime rehearsal (#29)

Both supported x86_64 distro containers run the stock native NGINX master
and its packaged unprivileged worker against a **detached, private** root.
The actual cache/log and per-repository owner-marker bootstrap and private
metrics inode bootstrap are invoked, rather than manually creating the
cache or log files. The joined route and metrics renderer then produces
the fragments for two local TLS routes; the CI harness remaps only the
validated public upstream pins and fixed log path to its disposable local
TLS fixture. This is not an installed service or production configuration.

Each repository must return unchanged metadata and artifact bytes with observable
MISS/HIT, one origin request, real worker-owned cache files, a root-owned
0600 metrics inode and eight correctly parsed events (four hits and four
misses) through the CLI's metrics reader. After stopping the process,
repeat preparation must preserve cached bytes/inodes, historical metrics
bytes, private inode and ownership marker. The test does not rotate a
live installed log, prove signed repository metadata, start systemd or
authenticate a host root. SELinux context policy and full installed
transaction/recovery remain separate #29/#31/#19 acceptance gates.

The workflow passes only the eight disposable privacy-limited log rows
as a short-lived CI artifact. A separate ordinary unprivileged CI job
runs the actual `repocache metrics show` JSON command on each exact
sample and checks observed counts and byte totals against the source
rows. It does not run the CLI with host-root privileges or transfer any
operator credentials, certificates, or production logs.

CI: `.github/workflows/server-v06-owned-storage-metrics-runtime.yml`.
