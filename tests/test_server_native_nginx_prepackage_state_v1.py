"""#27 pre-package #31 lock reuse. No NGINX, native manager or host mutation."""
from __future__ import annotations

from contextlib import contextmanager

import pytest

from repocache import server_native_nginx_prepackage_state_v1 as state


def absent_locked(monkeypatch):
    calls = []
    monkeypatch.setattr(state, "_read_journal",
                        lambda directory, uid: calls.append(("journal", uid)) or None)
    monkeypatch.setattr(state, "_read_file",
                        lambda directory, name, uid, limit:
                        calls.append(("file", name)) or None)
    monkeypatch.setattr(state, "_read_state",
                        lambda directory, uid: calls.append(("state", uid)) or (None, None))
    return calls


def test_empty_locked_state_requires_no_preexisting_nginx_tree(monkeypatch):
    calls = absent_locked(monkeypatch)
    result = state._check_under_lock(42)
    assert result["status"] == "LOCKED_PREPACKAGE_STATE_ABSENT"
    assert result["state_generation"] == 0
    assert result["exclusive_state_lock_held_during_inspection"]
    assert result["nginx_include_directory_required"] is False
    assert result["nginx_live_manifest_verified"] is False
    assert result["host_root_namespace_authenticated"] is False
    assert result["operator_authorization_verified"] is False
    assert result["native_transaction_journal_prepared"] is False
    assert result["authorizes_write"] is False
    assert result["authorizes_package_installation"] is False
    assert result["authorizes_nginx_reload"] is False
    assert calls[0] == ("journal", 0)
    assert len([c for c in calls if c[0] == "file"]) == 5
    assert len([c for c in calls if c[0] == "state"]) == 2


@pytest.mark.parametrize("name", [
    state.JOURNAL_TMP_NAME, state.STAGE_NAME, state.ROLLBACK_NAME,
])
def test_incomplete_transaction_requires_recovery_but_never_recovers(
    monkeypatch, name,
):
    monkeypatch.setattr(state, "_read_journal", lambda *_: None)
    monkeypatch.setattr(state, "_read_file",
                        lambda directory, path, uid, limit:
                        b"untrusted" if path == name else None)
    monkeypatch.setattr(state, "_read_state",
                        lambda *_: pytest.fail("no state read after recovery marker"))
    with pytest.raises(state.PrepackageStateInspectionError,
                       match="^PREPACKAGE_STATE_RECOVERY_REQUIRED$"):
        state._check_under_lock(15)


def test_existing_journal_refuses_before_state_access(monkeypatch):
    monkeypatch.setattr(state, "_read_journal", lambda *_: (None, "f" * 64, b"x"))
    monkeypatch.setattr(state, "_read_file", lambda *_:
                        pytest.fail("must not inspect next phase"))
    with pytest.raises(state.PrepackageStateInspectionError,
                       match="^PREPACKAGE_STATE_RECOVERY_REQUIRED$"):
        state._check_under_lock(12)


@pytest.mark.parametrize("existing", [(dict(state_generation=1), b"state"), (None, b"x")])
def test_existing_state_or_inconsistent_state_is_refused(monkeypatch, existing):
    absent_locked(monkeypatch)
    monkeypatch.setattr(state, "_read_state", lambda *_: existing)
    with pytest.raises(state.PrepackageStateInspectionError,
                       match="^PREPACKAGE_EXISTING_STATE_REFUSED$"):
        state._check_under_lock(9)


def test_state_appearing_during_read_is_refused(monkeypatch):
    absent_locked(monkeypatch)
    observations = iter(((None, None), ({"state_generation": 1}, b"x")))
    monkeypatch.setattr(state, "_read_state", lambda *_: next(observations))
    with pytest.raises(state.PrepackageStateInspectionError,
                       match="^PREPACKAGE_STATE_CHANGED$"):
        state._check_under_lock(9)


def test_no_root_identity_never_opens_any_directory(monkeypatch):
    monkeypatch.setattr(state.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(state.os, "open", lambda *_a, **_k:
                        pytest.fail("non-root must not open privileged state"))
    with pytest.raises(state.PrepackageStateInspectionError,
                       match="^PREPACKAGE_ROOT_PRIVILEGE_REQUIRED$"):
        state.inspect_current_namespace_prepackage_state()


def test_lock_and_current_namespace_root_are_checked_and_rechecked(monkeypatch):
    absent_locked(monkeypatch)
    monkeypatch.setattr(state.os, "geteuid", lambda: 0)
    history = []

    def check_root(root_fd):
        history.append(("root", root_fd))

    @contextmanager
    def fake_lock(root_fd, owner_uid):
        history.append(("locked", owner_uid))
        yield 42
        history.append(("unlocked", owner_uid))

    monkeypatch.setattr(state, "_verify_current_root_fd", check_root)
    monkeypatch.setattr(state, "_locked", fake_lock)
    result = state.inspect_current_namespace_prepackage_state()
    assert result["status"] == "LOCKED_PREPACKAGE_STATE_ABSENT"
    assert [x[0] for x in history] == [
        "root", "locked", "root", "root", "unlocked", "root"
    ]
    assert history[1][1] == history[-2][1] == 0


def test_unsafe_state_lock_error_is_redacted(monkeypatch):
    monkeypatch.setattr(state.os, "geteuid", lambda: 0)
    monkeypatch.setattr(state, "_verify_current_root_fd", lambda *_: None)

    @contextmanager
    def failing_lock(root_fd, owner_uid):
        raise state.ProtectedStateStoreError("sensitive host data")
        yield

    monkeypatch.setattr(state, "_locked", failing_lock)
    with pytest.raises(state.PrepackageStateInspectionError) as exc:
        state.inspect_current_namespace_prepackage_state()
    assert str(exc.value) == "PREPACKAGE_STATE_UNVERIFIED"


def test_no_pkg_service_or_network_calls_are_required(monkeypatch):
    absent_locked(monkeypatch)
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k:
                        pytest.fail("no external process expected"))
    assert state._check_under_lock(8)["authorizes_package_installation"] is False


@pytest.mark.parametrize("name", [
    state.NATIVE_PENDING_NAME,
    state.NATIVE_TMP_NAME,
])
def test_native_package_transaction_marker_blocks_fresh_snapshot(monkeypatch, name):
    monkeypatch.setattr(state, "_read_journal", lambda *_: None)
    monkeypatch.setattr(
        state, "_read_file",
        lambda directory, path, uid, limit: b"unknown-native-effects"
        if path == name else None,
    )
    monkeypatch.setattr(
        state, "_read_state",
        lambda *_: pytest.fail("never read generation after native effects marker"),
    )
    with pytest.raises(
        state.PrepackageStateInspectionError,
        match="^PREPACKAGE_NATIVE_EFFECTS_RECONCILIATION_REQUIRED$",
    ):
        state._check_under_lock(42)
