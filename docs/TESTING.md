# Testing and Evidence

Public pull-request CI must run Python and bundle smoke tests using disposable environments, including both Debian 13 and AlmaLinux 10. Tests are not equivalent to a security audit or live host compatibility certification.

Run the relevant unit, CLI, install, upgrade, signature, failover, concurrency, crash/recovery and offline-dependency tests on the exact reviewed source revision. Inspect job steps and logs, not merely workflow labels. Public v0.4.0 explicitly does not support pre-public in-place migrations. Run negative policy tests to ensure old installations are refused; confirm the historical prototype is absent from the distributed archive and cannot run. Synthetic migration/recovery tests verify mechanics, not actual prior-version compatibility. Do not present the superseded historical migration criterion as PASS.

An actual signed release, ruleset enforcement and a positive production readiness decision require separate owner approval and evidence. Never assert real systemd or SELinux host tests were executed when they were deferred.

For **every milestone**, use the [staged acceptance protocol](ACCEPTANCE_STAGES.md)
to distinguish CI-verifiable implementation, final booted native acceptance
and authentic signing/publication evidence. Each original issue's applicable
criterion retains an explicit PASS/FAIL/NOT VERIFIED status and exact source,
artifact, environment and run reference. An independently accepted CI-only
PR does not close a parent issue or certify operational native behavior.
