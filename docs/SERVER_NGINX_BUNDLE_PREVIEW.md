# Non-activating multi-repository NGINX preview (#28)

The internal function `render_pinned_repository_bundle` composes the existing
per-repository NGINX pin renderer into one ordered candidate for up to 64
repositories whose **desired state** is `active`. It is a pure Stage-A
preview, not a deployed configuration or a public CLI interface.

Callers must supply a separate complete, validated candidate address set for
every active repository. Missing, extra, disabled or unsafe candidate targets
refuse the **entire** preview. A deployment with no desired-active repositories
produces empty fragments and cannot implicitly expose a disabled source. Both
APT and DNF repositories retain independent cache zones and allowlisted HTTPS
origin verification. The fragments are intended for the managed `http{}`
and dedicated `server{}` contexts and still require a separately trusted
TLS listener and ownership-controlled installation.

The output does **not** prove current protected state, administrator approval,
trusted DNS provenance, available native NGINX directives, successful
`nginx -t`, a safe reload, a reachable route or catalog publication. All
activation/publication flags are false. Before any native promotion, #31/#64
must authenticate the source and write authority, stage the complete candidate,
verify native configuration and reload, confirm exposed routes, and atomically
publish only successfully active repositories. Failures must preserve or
restore the last known-good route/catalog generation.

Run `pytest -q tests/test_server_nginx_bundle_v1.py` to exercise
composition, privacy, invalid-last-target refusal, zero-route behavior and
the optional disposable stock-NGINX syntax check. A passing container-based
`nginx -t` is not booted Debian 13/AlmaLinux 10 systemd/SELinux acceptance.
