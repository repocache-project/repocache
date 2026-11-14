# AlmaLinux 10 disposable client approval dependency isolation (#24)

The existing native client-source approval CI workflow executes two real
approval/staging smoke scripts in disposable Debian 13 and AlmaLinux 10
containers, using only a read-only copy of the repository and ephemeral
container-internal state.

On 2026-11-14 the AlmaLinux job failed during its *prerequisite Python
installation*, before exercising either project smoke. DNF reported a
metadata parser error on the optional AlmaLinux `extras` repository.
The failure was not a failed REPOCACHE client transaction.

The fixture needs only `python3` from the distribution's base package
repositories. It now uses the native DNF5 invocation
`dnf --disable-repo=extras install -y python3` **for that one isolated
dependency installation**. The official base and AppStream repositories
remain available. DNF RPM signature checks, HTTPS verification and the
full original two smoke scripts are unchanged. The Debian APT branch and
the Docker read-only workspace bind mount are also unchanged.

`tests/test_client_entry_approval_workflow_repo_scope.py` prevents
accidental reintroduction of unscoped extras metadata or changes that
remove the smoke commands, disable package signature verification or
drop the read-only checkout. The actual workflow run on each distribution
remains the required functional evidence; a static regression test alone
is not a native acceptance test.

This is a **CI dependency-reliability correction**, not a client source
writer, native fallback implementation, production DNF repository policy
or release acceptance proof. Original #24 privileged apply/rollback,
package manager integration and booted #19 systemd/SELinux gates remain
NOT VERIFIED. Do not change production DNF configuration or use insecure
repository or signature options to work around metadata failures.
