"""Real disposable Linux inode/fsync and fail-closed native package journal tests."""
from __future__ import annotations

import json
import os

import pytest

from repocache.server_native_nginx_package_journal_v1 import (
    NATIVE_PENDING_NAME, NATIVE_TMP_NAME, NativePackageJournalError,
    _prepare_native_journal_under_root,
)
from repocache.server_protected_state_store_v1 import LOCK_NAME, STATE_NAME, _locked


@pytest.fixture
def protected_root(tmp_path):
    owner = os.geteuid()
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    folder = root
    for name in ("var", "lib", "repocache", "server"):
        folder = folder / name
        folder.mkdir(mode=0o700)
    # The real native OS has /var/cache before the package installer runs.
    # The signed installer must provision only its missing nginx leaf itself.
    (root / "var" / "cache").mkdir(mode=0o755)
    (folder / LOCK_NAME).write_bytes(b"")
    (folder / LOCK_NAME).chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd, folder, owner
    finally:
        os.close(fd)


@pytest.mark.parametrize("distribution,manager", [
    ("debian", "apt"), ("almalinux", "dnf"),
])
def test_durable_pending_marker_is_mode_0600_and_blocks_reentry(
    protected_root, distribution, manager,
):
    fd, folder, uid = protected_root
    result = _prepare_native_journal_under_root(
        fd, owner_uid=uid, distribution=distribution,
    )
    assert result["status"] == "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
    assert result["package_transaction_executed"] is False
    assert result["operator_authorization_authenticated"] is False
    assert result["native_package_signature_verified"] is False
    assert result["native_package_effects_reconciled"] is False
    assert result["authorizes_package_installation"] is False
    assert result["authorizes_nginx_reload"] is False
    pending = folder / NATIVE_PENDING_NAME
    assert pending.exists()
    assert (pending.stat().st_mode & 0o777) == 0o600
    assert pending.stat().st_nlink == 1
    assert not (folder / NATIVE_TMP_NAME).exists()
    doc = json.loads(pending.read_bytes())
    assert doc == {
        "journal_schema_version": 1,
        "operation": "fresh-native-nginx-package-install",
        "distribution": distribution,
        "manager": manager,
        "package": "nginx",
        "expected_state_generation": 0,
        "native_package_effects": "REQUIRES_EXPLICIT_RECONCILIATION",
    }
    assert not (folder / STATE_NAME).exists()
    with pytest.raises(NativePackageJournalError,
                       match="^NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED$"):
        _prepare_native_journal_under_root(
            fd, owner_uid=uid, distribution=distribution,
        )
    assert json.loads(pending.read_bytes()) == doc


@pytest.mark.parametrize("point", [
    "native_journal_temp_durable",
    "native_journal_link_durable",
    "native_journal_published",
])
def test_injected_crash_never_leaves_clean_reentry(protected_root, point):
    fd, folder, uid = protected_root

    def fail(phase):
        if phase == point:
            raise RuntimeError("simulated interruption")

    with pytest.raises(RuntimeError, match="simulated interruption"):
        _prepare_native_journal_under_root(
            fd, owner_uid=uid, distribution="debian", inject_fault=fail,
        )
    assert ((folder / NATIVE_TMP_NAME).exists()
            or (folder / NATIVE_PENDING_NAME).exists())
    with pytest.raises(NativePackageJournalError):
        _prepare_native_journal_under_root(
            fd, owner_uid=uid, distribution="debian",
        )


def test_existing_native_marker_refused_without_modification(protected_root):
    fd, folder, uid = protected_root
    marker = folder / NATIVE_PENDING_NAME
    marker.write_bytes(b"foreign")
    marker.chmod(0o600)
    with pytest.raises(NativePackageJournalError,
                       match="^NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED$"):
        _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    assert marker.read_bytes() == b"foreign"
    assert not (folder / NATIVE_TMP_NAME).exists()


def test_unsafe_symlinked_native_marker_refuses_closed(protected_root):
    fd, folder, uid = protected_root
    (folder / NATIVE_PENDING_NAME).symlink_to("/etc/passwd")
    with pytest.raises(NativePackageJournalError,
                       match="^NATIVE_JOURNAL_STATE_UNVERIFIED$"):
        _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    assert not (folder / NATIVE_TMP_NAME).exists()


def test_existing_protected_state_never_adopted_as_fresh(protected_root):
    fd, folder, uid = protected_root
    document = {
        "state_schema_version": 1,
        "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [],
        "ownership_manifest": [],
    }
    state = folder / STATE_NAME
    # #31 accepts only its canonical sorted/compact JSON encoding. A
    # noncanonical fixture is refused *before* the existing-generation gate.
    state.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    state.chmod(0o600)
    with pytest.raises(NativePackageJournalError,
                       match="^NATIVE_EXISTING_STATE_REFUSED$"):
        _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    assert not (folder / NATIVE_PENDING_NAME).exists()


def test_noncanonical_existing_state_fails_closed(protected_root):
    fd, folder, uid = protected_root
    state = folder / STATE_NAME
    state.write_text(json.dumps({
        "state_schema_version": 1,
        "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [],
        "ownership_manifest": [],
    }), encoding="ascii")
    state.chmod(0o600)
    with pytest.raises(NativePackageJournalError,
                       match="^NATIVE_JOURNAL_STATE_UNVERIFIED$"):
        _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    assert not (folder / NATIVE_PENDING_NAME).exists()


def test_invalid_inputs_rejected_before_lock_and_write(protected_root):
    fd, folder, uid = protected_root
    for distribution in ("ubuntu", "debian-12", None, True):
        with pytest.raises(NativePackageJournalError,
                           match="^NATIVE_JOURNAL_ARGUMENT_INVALID$"):
            _prepare_native_journal_under_root(
                fd, owner_uid=uid, distribution=distribution
            )
    assert not (folder / NATIVE_PENDING_NAME).exists()


def test_no_native_process_invoked_by_journal_writer(protected_root, monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k:
                        pytest.fail("journal never invokes native package manager"))
    fd, _, uid = protected_root
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="almalinux")


def test_concurrent_state_lock_prevents_second_journal_writer(protected_root):
    fd, folder, uid = protected_root
    from repocache.server_protected_state_store_v1 import ProtectedStateStoreError
    with _locked(fd, uid):
        with pytest.raises(NativePackageJournalError,
                           match="^NATIVE_JOURNAL_STATE_UNVERIFIED$"):
            _prepare_native_journal_under_root(
                fd, owner_uid=uid, distribution="debian",
            )
    assert not (folder / NATIVE_PENDING_NAME).exists()



@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_foreign_prejournal_refusal_under_lock_does_not_write_native_marker(
    protected_root, distribution,
):
    from repocache.server_native_nginx_package_journal_v1 import (
        _retain_native_package_journal_lock_under_root, NATIVE_COMPLETE_NAME,
    )
    from repocache.server_protected_state_store_v1 import ProtectedStateStoreError
    fd, folder, uid = protected_root
    called = []
    def deny_foreign():
        called.append(True)
        assert not (folder / NATIVE_PENDING_NAME).exists()
        assert not (folder / NATIVE_TMP_NAME).exists()
        with pytest.raises(ProtectedStateStoreError, match="PROTECTED_LOCK_UNAVAILABLE"):
            with _locked(fd, uid):
                pytest.fail("refusal-only preflight did not hold the root lock")
        raise ValueError("NATIVE_NGINX_FOREIGN_FOOTPRINT")
    with pytest.raises(ValueError, match="^NATIVE_NGINX_FOREIGN_FOOTPRINT$"):
        with _retain_native_package_journal_lock_under_root(
            fd, owner_uid=uid, distribution=distribution,
            preflight_before_journal=deny_foreign,
        ):
            pytest.fail("refused foreign host reached package transaction")
    assert called == [True]
    assert not any((folder / x).exists() for x in (
        NATIVE_PENDING_NAME, NATIVE_TMP_NAME, NATIVE_COMPLETE_NAME,
    ))
    # A stable preflight refusal must permit a later clean first-install.
    with _retain_native_package_journal_lock_under_root(
        fd, owner_uid=uid, distribution=distribution,
        preflight_before_journal=lambda: None,
    ) as result:
        assert result["status"] == "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
    assert (folder / NATIVE_PENDING_NAME).is_file()


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
@pytest.mark.parametrize("name", [
    NATIVE_PENDING_NAME, NATIVE_TMP_NAME, ".native-nginx-v1.completed",
])
def test_existing_native_marker_precedes_host_preflight_without_mutation(
    protected_root, distribution, name,
):
    """An interrupted install never reaches a fresh-host mask check."""
    from repocache.server_native_nginx_package_journal_v1 import (
        _retain_native_package_journal_lock_under_root,
    )

    root, state, owner = protected_root
    marker = state / name
    marker.write_bytes(b"previous-native-package-effects")
    marker.chmod(0o600)
    with pytest.raises(
        NativePackageJournalError,
        match="^NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED$",
    ):
        with _retain_native_package_journal_lock_under_root(
            root, owner_uid=owner, distribution=distribution,
            preflight_before_journal=lambda: pytest.fail(
                "interrupted native install reached fresh-host preflight",
            ),
        ):
            pytest.fail("interrupted native install reached execution scope")
    assert marker.read_bytes() == b"previous-native-package-effects"
    assert not (state / NATIVE_PENDING_NAME).exists() or name == NATIVE_PENDING_NAME
    assert not (state / NATIVE_TMP_NAME).exists() or name == NATIVE_TMP_NAME


def test_prejournal_guard_result_is_not_install_authority(protected_root):
    from repocache.server_native_nginx_package_journal_v1 import (
        _retain_native_package_journal_lock_under_root,
    )
    fd, folder, uid = protected_root
    with pytest.raises(NativePackageJournalError, match="NATIVE_JOURNAL_PREFLIGHT_INVALID"):
        with _retain_native_package_journal_lock_under_root(
            fd, owner_uid=uid, distribution="debian",
            preflight_before_journal=lambda: {"approved": True},
        ):
            pytest.fail("callback result must never grant authority")
    assert not (folder / NATIVE_PENDING_NAME).exists()


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_signed_native_foreign_precheck_refuses_before_journal_or_systemd(
    protected_root, monkeypatch, distribution,
):
    root, state, uid = protected_root
    installer, effects = _synthetic_host_native_package(monkeypatch, distribution)
    def foreign(*_a):
        raise ValueError("NATIVE_NGINX_FOREIGN_FOOTPRINT")
    monkeypatch.setattr(installer, "_fresh_nginx_under_lock", foreign)
    with pytest.raises(ValueError, match="^NATIVE_NGINX_FOREIGN_FOOTPRINT$"):
        installer._execute_native_nginx_install_locked(
            root, distribution=distribution, document={},
            os_release="", owner_uid=uid,
        )
    assert not (state / NATIVE_PENDING_NAME).exists()
    assert not (state / NATIVE_TMP_NAME).exists()
    assert effects["actions"] == [] and effects["commands"] == []


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_retained_lock_spans_package_effects_scope_and_blocks_concurrent_state(
    protected_root, distribution,
):
    from repocache.server_native_nginx_package_journal_v1 import (
        _retain_native_package_journal_lock_under_root,
    )
    from repocache.server_protected_state_store_v1 import ProtectedStateStoreError

    fd, folder, uid = protected_root
    with _retain_native_package_journal_lock_under_root(
        fd, owner_uid=uid, distribution=distribution,
    ) as status:
        assert status["status"] == "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
        assert status["operator_authorization_authenticated"] is False
        assert status["authorizes_package_installation"] is False
        assert (folder / NATIVE_PENDING_NAME).exists()
        assert not (folder / NATIVE_TMP_NAME).exists()
        # The fixed #31 lock is *still held* while the hypothetical native
        # package transaction executes. The legacy short-lived preparer
        # cannot reenter, even from a second file descriptor in this process.
        with pytest.raises(ProtectedStateStoreError,
                           match="^PROTECTED_LOCK_UNAVAILABLE$"):
            with _locked(fd, uid):
                pytest.fail("concurrent state lock admitted")
        with pytest.raises(NativePackageJournalError,
                           match="^NATIVE_JOURNAL_STATE_UNVERIFIED$"):
            _prepare_native_journal_under_root(
                fd, owner_uid=uid, distribution=distribution,
            )
    # Once the transaction ends, the pending marker is still durable.
    # It must NEVER be interpreted as package installation completion.
    assert (folder / NATIVE_PENDING_NAME).exists()
    with pytest.raises(NativePackageJournalError,
                       match="^NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED$"):
        _prepare_native_journal_under_root(
            fd, owner_uid=uid, distribution=distribution,
        )


def test_native_package_operation_exception_leaves_pending_hard_stop(
    protected_root,
):
    from repocache.server_native_nginx_package_journal_v1 import (
        _retain_native_package_journal_lock_under_root,
    )
    fd, folder, uid = protected_root
    with pytest.raises(RuntimeError, match="simulated native package error"):
        with _retain_native_package_journal_lock_under_root(
            fd, owner_uid=uid, distribution="debian",
        ) as status:
            assert status["package_transaction_executed"] is False
            assert (folder / NATIVE_PENDING_NAME).exists()
            raise RuntimeError("simulated native package error")
    with pytest.raises(NativePackageJournalError,
                       match="^NATIVE_PACKAGE_EFFECTS_RECONCILIATION_REQUIRED$"):
        _prepare_native_journal_under_root(
            fd, owner_uid=uid, distribution="debian",
        )


@pytest.mark.parametrize("dist", ["debian", "almalinux"])
def test_fault_before_lock_scope_yields_never_run_package_effects(
    protected_root, dist,
):
    from repocache.server_native_nginx_package_journal_v1 import (
        _retain_native_package_journal_lock_under_root,
    )
    fd, folder, uid = protected_root
    with pytest.raises(RuntimeError, match="before package"):
        with _retain_native_package_journal_lock_under_root(
            fd, owner_uid=uid, distribution=dist,
            inject_fault=lambda point: (
                (_ for _ in ()).throw(RuntimeError("before package"))
                if point == "native_journal_link_durable" else None
            ),
        ):
            pytest.fail("package callback reached despite journal fault")
    assert ((folder / NATIVE_PENDING_NAME).exists()
            or (folder / NATIVE_TMP_NAME).exists())
    with pytest.raises(NativePackageJournalError):
        _prepare_native_journal_under_root(fd, owner_uid=uid, distribution=dist)

@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_native_package_completion_is_durable_and_requires_exact_locked_facts(
    protected_root, monkeypatch, distribution,
):
    from repocache import server_native_package_effects_observe_v1 as observe
    from repocache.server_native_nginx_package_journal_v1 import (
        NATIVE_COMPLETE_NAME, _complete_native_install_after_verified_manager_under_lock,
        _read_completed_native_install_under_lock,
    )
    fd, folder, uid = protected_root
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution=distribution)
    pending = (folder / NATIVE_PENDING_NAME).read_bytes()
    before = {
        "status": "NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION",
        "distribution": distribution,
        "journal_identity_verified": True,
        "pending_native_effects_block_reentry": True,
        "authorizes_native_marker_removal": False,
    }
    package = {
        "platform": "debian13" if distribution == "debian" else "almalinux10",
        "package_name": "nginx" if distribution == "debian" else "nginx-core",
        "binary_path": "/usr/sbin/nginx",
        "status": "READ_ONLY_STOCK_NGINX_PACKAGE_OWNER_OBSERVED",
        "native_package_db_owner_observed": True,
        "native_package_signature_verified": False,
        "authorizes_nginx_adoption": False,
    }
    integrity = {
        "status": "READ_ONLY_STOCK_NGINX_PACKAGE_FILE_INTEGRITY_OBSERVED",
        "platform": package["platform"],
        "native_package_file_integrity_verified": True,
        "native_package_signature_verified": False,
        "authorizes_native_marker_removal": False,
        "authorizes_nginx_activation": False,
    }
    unit = {
        "unit_name": "nginx.service",
        "code": "VENDOR_NGINX_UNIT_OBSERVED",
        "vendor_unit_sha256": "a" * 64,
        "vendor_unit_bounded_and_owned": True,
        "native_package_file_ownership_verified": False,
        "authorizes_systemctl": False,
        "authorizes_nginx_reload": False,
    }
    monkeypatch.setattr(
        observe, "_collect_postpackage_facts_while_locked",
        lambda state, *, owner_uid, distribution:
            (before, package, integrity, unit, dict(before)),
    )
    with _locked(fd, uid) as state:
        result = _complete_native_install_after_verified_manager_under_lock(
            state, owner_uid=uid, distribution=distribution,
        )
        assert result["native_package_effects_reconciled"] is True
        receipt = _read_completed_native_install_under_lock(
            state, owner_uid=uid, distribution=distribution,
        )
        assert receipt["pending_sha256"] == __import__("hashlib").sha256(pending).hexdigest()
        assert receipt["vendor_unit_sha256"] == "a" * 64
        assert receipt["publisher_artifact_verified"] is False
    assert not (folder / NATIVE_PENDING_NAME).exists()
    assert (folder / NATIVE_COMPLETE_NAME).exists()
    with pytest.raises(NativePackageJournalError):
        _prepare_native_journal_under_root(
            fd, owner_uid=uid, distribution=distribution,
        )
    assert (folder / NATIVE_COMPLETE_NAME).exists()


@pytest.mark.parametrize("unsafe", [
    "foreign-package", "invalid-unit", "missing-integrity",
])
def test_native_completion_refuses_untrusted_facts_with_pending_intact(
    protected_root, monkeypatch, unsafe,
):
    from repocache import server_native_package_effects_observe_v1 as observe
    from repocache.server_native_nginx_package_journal_v1 import (
        NATIVE_COMPLETE_NAME, _complete_native_install_after_verified_manager_under_lock,
    )
    fd, folder, uid = protected_root
    _prepare_native_journal_under_root(fd, owner_uid=uid, distribution="debian")
    raw = (folder / NATIVE_PENDING_NAME).read_bytes()
    before = {
        "status": "NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION",
        "distribution": "debian",
        "journal_identity_verified": True,
        "pending_native_effects_block_reentry": True,
        "authorizes_native_marker_removal": False,
    }
    package = {
        "platform": "debian13", "package_name": "nginx",
        "binary_path": "/usr/sbin/nginx",
        "status": "READ_ONLY_STOCK_NGINX_PACKAGE_OWNER_OBSERVED",
        "native_package_db_owner_observed": True,
        "native_package_signature_verified": False,
        "authorizes_nginx_adoption": False,
    }
    integrity = {
        "status": "READ_ONLY_STOCK_NGINX_PACKAGE_FILE_INTEGRITY_OBSERVED",
        "platform": "debian13",
        "native_package_file_integrity_verified": True,
        "native_package_signature_verified": False,
        "authorizes_native_marker_removal": False,
        "authorizes_nginx_activation": False,
    }
    unit = {
        "unit_name": "nginx.service", "code": "VENDOR_NGINX_UNIT_OBSERVED",
        "vendor_unit_sha256": "a" * 64,
        "vendor_unit_bounded_and_owned": True,
        "native_package_file_ownership_verified": False,
        "authorizes_systemctl": False, "authorizes_nginx_reload": False,
    }
    if unsafe == "foreign-package":
        package["package_name"] = "foreign"
    elif unsafe == "invalid-unit":
        unit["code"] = "VENDOR_NGINX_SHADOW_REFUSED"
    else:
        integrity["native_package_file_integrity_verified"] = False
    monkeypatch.setattr(
        observe, "_collect_postpackage_facts_while_locked",
        lambda *_a, **_kw:
            (before, package, integrity, unit, dict(before)),
    )
    with _locked(fd, uid) as state:
        with pytest.raises(NativePackageJournalError, match="NATIVE_COMPLETION_AUDIT_UNVERIFIED"):
            _complete_native_install_after_verified_manager_under_lock(
                state, owner_uid=uid, distribution="debian",
            )
    assert (folder / NATIVE_PENDING_NAME).read_bytes() == raw
    assert not (folder / NATIVE_COMPLETE_NAME).exists()



def test_native_completion_scope_expires_and_never_auto_clears(protected_root):
    from repocache.server_native_nginx_package_journal_v1 import (
        _retain_native_package_journal_lock_under_root,
        NATIVE_COMPLETE_NAME,
    )
    fd, folder, uid = protected_root
    with _retain_native_package_journal_lock_under_root(
        fd, owner_uid=uid, distribution="debian",
        expose_audited_completion=True,
    ) as report:
        finish = report["_complete_under_lock"]
        assert callable(finish)
        assert (folder / NATIVE_PENDING_NAME).exists()
        assert not (folder / NATIVE_COMPLETE_NAME).exists()
        # No pre-existing install proof: no callback call is permitted merely
        # because the journal is well-formed.
    with pytest.raises(NativePackageJournalError, match="NATIVE_COMPLETION_SCOPE_EXPIRED"):
        finish()
    assert (folder / NATIVE_PENDING_NAME).exists()
    assert not (folder / NATIVE_COMPLETE_NAME).exists()


def test_completion_callback_is_single_use_even_after_failure(
    protected_root, monkeypatch,
):
    from repocache import server_native_package_effects_observe_v1 as observe
    from repocache.server_native_nginx_package_journal_v1 import (
        _retain_native_package_journal_lock_under_root,
    )
    fd, folder, uid = protected_root
    monkeypatch.setattr(
        observe, "_collect_postpackage_facts_while_locked",
        lambda *_a, **_kw: (_ for _ in ()).throw(ValueError("unverified native")),
    )
    with _retain_native_package_journal_lock_under_root(
        fd, owner_uid=uid, distribution="debian",
        expose_audited_completion=True,
    ) as report:
        finish = report["_complete_under_lock"]
        with pytest.raises(NativePackageJournalError, match="NATIVE_COMPLETION_AUDIT_UNVERIFIED"):
            finish()
        with pytest.raises(NativePackageJournalError, match="NATIVE_COMPLETION_SCOPE_EXPIRED"):
            finish()
    assert (folder / NATIVE_PENDING_NAME).exists()


def _synthetic_host_native_package(monkeypatch, distribution, *, failure=None):
    """Mock host effects, retain real root-FD journal, lock and audit receipt."""
    from types import SimpleNamespace
    from scripts import install_native_root_worker as install
    from repocache import server_native_package_effects_observe_v1 as observe
    mask = {"active": False, "disabled": False, "actions": [], "commands": []}
    original_lexists = os.path.lexists
    monkeypatch.setattr(install.os.path, "lexists", lambda path: (
        mask["active"] if path == install._NGINX_MASK else original_lexists(path)))
    monkeypatch.setattr(install, "_owned_nginx_mask", lambda: mask["active"])
    monkeypatch.setattr(install, "_native_workspace_is_root_owned", lambda _path: True)
    monkeypatch.setattr(install, "_fresh_nginx_under_lock", lambda *_args: None)
    monkeypatch.setattr(install, "_trusted_key", lambda _path: True)
    monkeypatch.setattr(install, "_native_install_commands",
                        lambda distro, work: (["REFRESH"], ["INSTALL"]))
    def systemctl(action):
        mask["actions"].append(action)
        if action == "mask":
            mask["active"] = True
            return 0, b""
        if action == "disable":
            mask["disabled"] = True
            return 0, b""
        if action == "unmask":
            mask["active"] = False
            return 0, b""
        if action == "is-enabled":
            return (1, b"disabled\n") if mask["disabled"] else (0, b"enabled\n")
        if action == "is-active":
            return 3, b"inactive\n"
        pytest.fail("unexpected systemctl operation")
    monkeypatch.setattr(install, "_nginx_systemctl", systemctl)
    def run(argv, _work):
        mask["commands"].append(tuple(argv))
        if failure == "manager" and argv[0] == "INSTALL":
            raise ValueError("simulated package transaction failure")
        if argv[0] == "/usr/bin/dpkg-query":
            return "install ok installed"
        if argv[0] == "/usr/bin/rpm":
            return "nginx"
        return ""
    monkeypatch.setattr(install, "_native_package_command", run)
    platform = "debian13" if distribution == "debian" else "almalinux10"
    pkg = {"platform": platform, "package_name": "nginx" if distribution == "debian" else "nginx-core",
           "binary_path": "/usr/sbin/nginx",
           "status": "READ_ONLY_STOCK_NGINX_PACKAGE_OWNER_OBSERVED",
           "native_package_db_owner_observed": True,
           "native_package_signature_verified": False, "authorizes_nginx_adoption": False}
    integrity = {"status": "READ_ONLY_STOCK_NGINX_PACKAGE_FILE_INTEGRITY_OBSERVED",
                 "platform": platform, "native_package_file_integrity_verified": True,
                 "native_package_signature_verified": False,
                 "authorizes_native_marker_removal": False, "authorizes_nginx_activation": False}
    unit = {"unit_name": "nginx.service", "code": "VENDOR_NGINX_UNIT_OBSERVED",
            "vendor_unit_sha256": "a" * 64, "vendor_unit_bounded_and_owned": True,
            "native_package_file_ownership_verified": False,
            "authorizes_systemctl": False, "authorizes_nginx_reload": False}
    observed = {"status": "NATIVE_PACKAGE_EFFECTS_PENDING_RECONCILIATION",
                "distribution": distribution, "journal_identity_verified": True,
                "pending_native_effects_block_reentry": True,
                "authorizes_native_marker_removal": False}
    monkeypatch.setattr(install, "inspect_stock_nginx_package_owner", lambda: pkg)
    monkeypatch.setattr(install, "inspect_stock_nginx_package_file_integrity", lambda: integrity)
    monkeypatch.setattr(install, "inspect_native_nginx_unit",
                        lambda distro: SimpleNamespace(to_dict=lambda: unit))
    def audit(_state, *, owner_uid, distribution):
        if failure == "audit":
            raise observe.NativeEffectsReconciliationError("simulated audit failure")
        return observed, pkg, integrity, unit, dict(observed)
    monkeypatch.setattr(observe, "_collect_postpackage_facts_while_locked", audit)
    return install, mask


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_signed_native_host_scope_completes_only_after_service_disabled_and_audit(
    protected_root, monkeypatch, distribution,
):
    from repocache.server_native_nginx_package_journal_v1 import NATIVE_COMPLETE_NAME
    root_fd, state, uid = protected_root
    install, mask = _synthetic_host_native_package(monkeypatch, distribution)
    result = install._execute_native_nginx_install_locked(
        root_fd, distribution=distribution, document={}, os_release="", owner_uid=uid,
    )
    assert result["status"] == "AUTHENTICATED_NATIVE_NGINX_PACKAGE_INSTALLED"
    assert result["authorizes_service_activation"] is False
    assert mask["actions"] == ["mask", "disable", "unmask", "is-enabled", "is-active"]
    assert not mask["active"]
    assert (state / NATIVE_COMPLETE_NAME).is_file()
    assert not (state / NATIVE_PENDING_NAME).exists()
    with pytest.raises(NativePackageJournalError):
        install._execute_native_nginx_install_locked(
            root_fd, distribution=distribution, document={}, os_release="", owner_uid=uid,
        )


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
@pytest.mark.parametrize("failure", ["manager", "audit"])
def test_signed_native_host_scope_rejects_partial_effects_and_retains_durable_mask(
    protected_root, monkeypatch, distribution, failure,
):
    from repocache.server_native_nginx_package_journal_v1 import NATIVE_COMPLETE_NAME
    root_fd, state, uid = protected_root
    install, mask = _synthetic_host_native_package(monkeypatch, distribution, failure=failure)
    with pytest.raises(ValueError):
        install._execute_native_nginx_install_locked(
            root_fd, distribution=distribution, document={}, os_release="", owner_uid=uid,
        )
    assert (state / NATIVE_PENDING_NAME).is_file()
    assert not (state / NATIVE_COMPLETE_NAME).exists()
    assert mask["active"]
    with pytest.raises(NativePackageJournalError):
        install._execute_native_nginx_install_locked(
            root_fd, distribution=distribution, document={}, os_release="", owner_uid=uid,
        )


@pytest.mark.parametrize("name", [
    "state-v2.json", ".state-v2.pending", ".state-v2-native.pending",
    ".admin-candidate-v2", ".native-worker-placement.pending-bad",
    ".foreign", ".native-worker-placement.complete-" + "g" * 64,
])
def test_fresh_native_package_never_adopts_v2_or_unknown_protected_state(
    protected_root, name,
):
    root, state, owner = protected_root
    unexpected = state / name
    unexpected.write_bytes(b"")
    unexpected.chmod(0o600)
    # The protected lock can detect legacy/v2 cohabitation even before the
    # native fresh-state allowlist runs. Both paths MUST refuse without writes.
    with pytest.raises(
        NativePackageJournalError,
        match="NATIVE_(?:FOREIGN_PROTECTED_STATE|JOURNAL_STATE_UNVERIFIED)",
    ):
        _prepare_native_journal_under_root(root, owner_uid=owner, distribution="debian")
    assert unexpected.is_file()
    assert not (state / NATIVE_PENDING_NAME).exists()


def test_fresh_native_package_can_follow_exact_authenticated_worker_placement_receipt(
    protected_root,
):
    root, state, owner = protected_root
    marker = state / (".native-worker-placement.complete-" + "a" * 64)
    marker.write_bytes(b"")
    marker.chmod(0o600)
    result = _prepare_native_journal_under_root(root, owner_uid=owner, distribution="debian")
    assert result["status"] == "NATIVE_PACKAGE_EFFECTS_JOURNAL_DURABLE"
    assert marker.exists() and (state / NATIVE_PENDING_NAME).is_file()


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
@pytest.mark.parametrize("action", ["mask", "disable", "unmask", "is-enabled", "is-active"])
@pytest.mark.parametrize("failure", ["reported_error", "raised_error"])
def test_native_service_fault_matrix_retains_pending_and_prevents_retry(
    protected_root, monkeypatch, distribution, action, failure,
):
    """Every systemctl failure is non-committing; unmask errors re-mask."""
    from repocache.server_native_nginx_package_journal_v1 import NATIVE_COMPLETE_NAME

    root, state, owner = protected_root
    install, effects = _synthetic_host_native_package(monkeypatch, distribution)
    original = install._nginx_systemctl
    seen = []

    def failed_systemctl(operation):
        if operation != action or seen:
            return original(operation)
        seen.append(operation)
        original(operation)  # Error after an observable effect, not a no-op.
        if failure == "raised_error":
            raise ValueError("interrupted systemctl")
        if operation == "is-enabled":
            return 0, b"enabled\n"
        if operation == "is-active":
            return 0, b"active\n"
        return 1, b"failed\n"

    monkeypatch.setattr(install, "_nginx_systemctl", failed_systemctl)
    with pytest.raises(ValueError):
        install._execute_native_nginx_install_locked(
            root, distribution=distribution, document={}, os_release="", owner_uid=owner,
        )
    assert seen == [action]
    assert effects["active"], "must remain masked or re-mask after service fault"
    if action == "mask":
        assert not effects["commands"], "package manager ran without a proven mask"
    else:
        assert ("INSTALL",) in effects["commands"]
    marker = state / NATIVE_PENDING_NAME
    raw = marker.read_bytes()
    assert json.loads(raw)["native_package_effects"] == "REQUIRES_EXPLICIT_RECONCILIATION"
    assert not (state / NATIVE_COMPLETE_NAME).exists()
    with pytest.raises(NativePackageJournalError):
        install._execute_native_nginx_install_locked(
            root, distribution=distribution, document={}, os_release="", owner_uid=owner,
        )
    assert marker.read_bytes() == raw


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
@pytest.mark.parametrize("phase", [
    "refresh", "install", "package-status", "nginx-syntax",
    "stock-owner", "file-integrity", "vendor-unit", "completion-audit",
])
def test_native_package_and_audit_fault_matrix_never_commits_partial_effects(
    protected_root, monkeypatch, distribution, phase,
):
    """Inject errors after effects, between APT/DNF and the fsynced receipt."""
    from repocache.server_native_nginx_package_journal_v1 import NATIVE_COMPLETE_NAME
    from repocache import server_native_package_effects_observe_v1 as observe

    root, state, owner = protected_root
    install, effects = _synthetic_host_native_package(monkeypatch, distribution)
    reached = []

    def interrupted(func):
        def call(*args, **kwargs):
            value = func(*args, **kwargs)
            reached.append(phase)
            raise ValueError("interrupted " + phase)
        return call

    if phase in ("refresh", "install", "package-status", "nginx-syntax"):
        original = install._native_package_command

        def command(argv, work):
            value = original(argv, work)
            current = (
                "refresh" if argv[0] == "REFRESH" else
                "install" if argv[0] == "INSTALL" else
                "package-status" if argv[0] in ("/usr/bin/dpkg-query", "/usr/bin/rpm") else
                "nginx-syntax" if argv[0] == "/usr/sbin/nginx" else None
            )
            if current == phase:
                reached.append(phase)
                raise ValueError("interrupted " + phase)
            return value

        monkeypatch.setattr(install, "_native_package_command", command)
    else:
        target, attr = {
            "stock-owner": (install, "inspect_stock_nginx_package_owner"),
            "file-integrity": (install, "inspect_stock_nginx_package_file_integrity"),
            "vendor-unit": (install, "inspect_native_nginx_unit"),
            "completion-audit": (observe, "_collect_postpackage_facts_while_locked"),
        }[phase]
        monkeypatch.setattr(target, attr, interrupted(getattr(target, attr)))

    with pytest.raises(ValueError):
        install._execute_native_nginx_install_locked(
            root, distribution=distribution, document={}, os_release="", owner_uid=owner,
        )
    assert reached == [phase]
    assert effects["active"]
    marker = state / NATIVE_PENDING_NAME
    raw = marker.read_bytes()
    assert json.loads(raw)["distribution"] == distribution
    assert not (state / NATIVE_COMPLETE_NAME).exists()
    with pytest.raises(NativePackageJournalError):
        _prepare_native_journal_under_root(
            root, owner_uid=owner, distribution=distribution,
        )
    assert marker.read_bytes() == raw


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
@pytest.mark.parametrize("phase", [
    "post-install", "post-disable", "post-unmask", "post-is-enabled", "post-is-active",
])
def test_non_exception_abrupt_stop_keeps_reentry_blocked(
    protected_root, monkeypatch, distribution, phase,
):
    """Model unexpected process termination (not actual SIGKILL or service proof)."""
    from repocache.server_native_nginx_package_journal_v1 import NATIVE_COMPLETE_NAME
    root, state, owner = protected_root
    install, _ = _synthetic_host_native_package(monkeypatch, distribution)
    systemctl, package = install._nginx_systemctl, install._native_package_command
    hit = []

    def control(action):
        result = systemctl(action)
        if phase == "post-" + action:
            hit.append(phase)
            raise KeyboardInterrupt("abrupt native stop")
        return result

    def command(argv, work):
        result = package(argv, work)
        if phase == "post-install" and argv[0] == "INSTALL":
            hit.append(phase)
            raise KeyboardInterrupt("abrupt native stop")
        return result

    monkeypatch.setattr(install, "_nginx_systemctl", control)
    monkeypatch.setattr(install, "_native_package_command", command)
    with pytest.raises(KeyboardInterrupt, match="abrupt native stop"):
        install._execute_native_nginx_install_locked(
            root, distribution=distribution, document={}, os_release="", owner_uid=owner,
        )
    assert hit == [phase]
    marker = state / NATIVE_PENDING_NAME
    raw = marker.read_bytes()
    assert not (state / NATIVE_COMPLETE_NAME).exists()
    with pytest.raises(NativePackageJournalError):
        _prepare_native_journal_under_root(
            root, owner_uid=owner, distribution=distribution,
        )
    assert marker.read_bytes() == raw
    # After unmask, the service mask can be absent until native reconciliation.
    # This test proves journal durability, not booted-host service containment.


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
@pytest.mark.parametrize("interruption", [
    "after-completion-receipt-fsync", "after-pending-marker-unlink-fsync",
])
def test_abrupt_completion_boundary_never_loses_both_audit_markers(
    protected_root, monkeypatch, distribution, interruption,
):
    """Crash after a durable operation must not create a clean reentry window."""
    from repocache import server_native_nginx_package_journal_v1 as journal

    root, state, owner = protected_root
    install, _ = _synthetic_host_native_package(monkeypatch, distribution)
    original_write = journal._write_exclusive
    original_unlink = journal._unlink_known
    injected = []

    def after_write(directory, name, *args, **kwargs):
        result = original_write(directory, name, *args, **kwargs)
        if (name == journal.NATIVE_COMPLETE_NAME
                and interruption == "after-completion-receipt-fsync"):
            injected.append(name)
            raise KeyboardInterrupt("interrupted after receipt fsync")
        return result

    def after_unlink(directory, name, *args, **kwargs):
        result = original_unlink(directory, name, *args, **kwargs)
        if (name == journal.NATIVE_PENDING_NAME
                and interruption == "after-pending-marker-unlink-fsync"):
            injected.append(name)
            raise KeyboardInterrupt("interrupted after pending unlink fsync")
        return result

    monkeypatch.setattr(journal, "_write_exclusive", after_write)
    monkeypatch.setattr(journal, "_unlink_known", after_unlink)
    with pytest.raises(KeyboardInterrupt, match="interrupted after"):
        install._execute_native_nginx_install_locked(
            root, distribution=distribution, document={}, os_release="", owner_uid=owner,
        )
    assert len(injected) == 1
    completed = state / journal.NATIVE_COMPLETE_NAME
    assert completed.is_file()
    receipt = json.loads(completed.read_bytes())
    assert receipt["distribution"] == distribution
    assert receipt["publisher_artifact_verified"] is False
    pending = state / NATIVE_PENDING_NAME
    assert pending.exists() == (interruption == "after-completion-receipt-fsync")
    if pending.exists():
        import hashlib
        assert receipt["pending_sha256"] == hashlib.sha256(pending.read_bytes()).hexdigest()
    preserved = completed.read_bytes()
    with pytest.raises(NativePackageJournalError):
        _prepare_native_journal_under_root(
            root, owner_uid=owner, distribution=distribution,
        )
    assert completed.read_bytes() == preserved
