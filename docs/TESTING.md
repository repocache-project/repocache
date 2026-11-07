# Testing and Evidence

Public pull-request CI must run Python and bundle smoke tests using disposable environments, including both Debian 13 and AlmaLinux 10. Tests are not equivalent to a security audit or live host compatibility certification.

Run the relevant unit, CLI, install, upgrade, signature, failover, concurrency, crash/recovery and offline-dependency tests on the exact reviewed source revision. Inspect job steps and logs, not merely workflow labels. Public v0.4.0 explicitly does not support pre-public in-place migrations. Run negative policy tests to ensure old installations are refused; confirm the historical prototype is absent from the distributed archive and cannot run. Synthetic migration/recovery tests verify mechanics, not actual prior-version compatibility. Do not present the superseded historical migration criterion as PASS.

An actual signed release, ruleset enforcement and a positive production readiness decision require separate owner approval and evidence. Never assert real systemd or SELinux host tests were executed when they were deferred.

**First operational v0.6.0 (owner decision 2026-11-07):** the old public v0.4.0 -> v0.6.0 compatibility/upgrade path is explicitly unsupported and is not an acceptance test. Verify fresh signed v0.6.0 installs, same-version repair, fail-closed refusal of legacy state, native NGINX/SELinux operations and future recovery. Historical v0.4.0 publication evidence remains intact; the old executable is not run as a v0.6.0 gate.
