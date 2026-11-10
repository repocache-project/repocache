"""Real descriptor-FD native v2 WAL and service compensation in disposable roots.

All filesystem effects occur within pytest tmp_path. Systemd, TLS, native
NGINX and network are monkeypatched; actual booted host/SELinux are not tested.
These are production-engine transaction tests, NOT signed installed acceptance.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

import repocache.server_native_v2_transaction_v1 as native
from repocache.server_protected_state_store_v1 import LOCK_NAME
from repocache.server_proposed_state_v2_store import V2_STATE
from repocache.server_root_control_fixed_candidate_v1 import _NAME
from test_server_proposed_state_v2_store import snapshot, document

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0, reason="requires disposable root-owned Linux directories",
)


def _canon(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


@pytest.fixture
def filesystem(tmp_path, monkeypatch):
    root = tmp_path / "native-owned-root"
    root.mkdir(mode=0o700)
    for parts, mode in [
        (("var", "lib", "repocache", "server"), 0o700),
        (("var", "lib", "repocache", "public"), 0o755),
        (("etc", "nginx", "conf.d"), 0o755),
    ]:
        current = root
        for part in parts:
            current /= part
            if not current.exists():
                current.mkdir(mode=mode if part in ("server", "public", "conf.d")
                              else 0o755)
        current.chmod(mode)
    state = root / "var/lib/repocache/server"
    include = root / "etc/nginx/conf.d" / native._INCLUDE
    catalog = root / "var/lib/repocache/public" / native._CATALOG
    lock = state / LOCK_NAME
    lock.write_bytes(b"")
    lock.chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    events = []
    monkeypatch.setattr(native, "_verify_tls_pair",
                        lambda *_: events.append("tls"))
    monkeypatch.setattr(native, "_native_syntax_check",
                        lambda: events.append("syntax"))
    monkeypatch.setattr(native, "_reload_native",
                        lambda distro: events.append(("reload", distro)))
    monkeypatch.setattr(native, "_local_https_generation",
                        lambda document, generation: events.append(
                            ("exposure", generation)))
    monkeypatch.setattr(native, "_route_dump_check",
                        lambda *_args: events.append("dump"))
    monkeypatch.setattr(native, "_local_https_catalog",
                        lambda _doc, raw: events.append(("catalog-exposure", len(raw))))
    try:
        yield fd, state, include, catalog, events
    finally:
        os.close(fd)


def stage(fs, next_state, *, prior=None, expected=0):
    _fd, state, _include, _catalog, _events = fs
    raw = _canon(next_state)
    request = {
        "request_schema_version": 1,
        "expected_generation": expected,
        "expected_state_sha256": prior,
        "next_state_base64": base64.b64encode(raw).decode("ascii"),
        "next_state_sha256": hashlib.sha256(raw).hexdigest(),
    }
    path = state / _NAME
    path.write_bytes(_canon(request))
    path.chmod(0o600)
    return path


def apply(fs):
    return native._operation_under_root(
        fs[0], distribution="debian", operation="APPLY_V2", fixture=True,
    )


def recover(fs):
    return native._operation_under_root(
        fs[0], distribution="debian", operation="RECOVER_V2", fixture=True,
    )


def assert_no_pending(fs):
    _, state, include, catalog, _events = fs
    assert not (state / native._WAL).exists()
    assert not (state / native._WAL_TMP).exists()
    assert not (state / native._STATE_STAGE).exists()
    assert not (state / native._MANIFEST_STAGE).exists()
    assert not (include.parent / native._STAGE).exists()
    assert not (catalog.parent / native._STAGE).exists()


def test_first_install_commits_real_three_resource_paths(filesystem, monkeypatch):
    stage(filesystem, snapshot(count=1))
    _fd, state, include, catalog, events = filesystem
    actual = native._write_public

    def observed_write(parent, name, before, after, maximum):
        if name == native._CATALOG:
            assert ("exposure", 1) in events
            assert "dump" in events
            assert (state / native._WAL).exists()
        return actual(parent, name, before, after, maximum)

    monkeypatch.setattr(native, "_write_public", observed_write)
    result = apply(filesystem)
    assert result["status"] == "NATIVE_V2_COMMITTED"
    assert result["active_catalog_published"] is True
    assert events == ["tls", "syntax", ("reload", "debian"),
                      ("exposure", 1), "dump",
                      ("catalog-exposure", len(catalog.read_bytes()))]
    assert (state / V2_STATE).is_file()
    assert include.stat().st_mode & 0o777 == 0o644
    assert catalog.stat().st_mode & 0o777 == 0o644
    assert json.loads(catalog.read_text()) == {"schema": 1, "repositories": []}
    assert (state / native._MANIFEST).is_file()
    assert recover(filesystem)["status"] == "NATIVE_V2_CLEAN"
    assert_no_pending(filesystem)


@pytest.mark.parametrize("step", ["syntax", "reload", "exposure", "dump", "catalog"])
def test_failed_native_phase_rolls_back_previous_bytes(filesystem, monkeypatch,
                                                       step):
    stage(filesystem, snapshot(count=1))
    _fd, state, include, catalog, events = filesystem
    targets = {
        "syntax": ("_native_syntax_check", "syntax"),
        "reload": ("_reload_native", ("reload", "debian")),
        "exposure": ("_local_https_generation", ("exposure", 1)),
        "dump": ("_route_dump_check", "dump"),
        "catalog": ("_local_https_catalog", "catalog"),
    }
    function, marker = targets[step]
    old = getattr(native, function)
    attempts = []

    def fail_once(*args):
        attempts.append(1)
        if len(attempts) == 1:
            raise native.NativeV2TransactionError("SIMULATED_REFUSAL")
        return old(*args)

    monkeypatch.setattr(native, function, fail_once)
    with pytest.raises(native.NativeV2TransactionError,
                       match="APPLY_FAILED_ROLLED_BACK"):
        apply(filesystem)
    assert attempts
    assert not (state / V2_STATE).exists()
    assert not include.exists()
    assert not catalog.exists()
    assert not (state / native._MANIFEST).exists()
    assert_no_pending(filesystem)
    assert recover(filesystem)["status"] == "NATIVE_V2_CLEAN"


def test_sigkill_equivalent_preserves_wal_for_second_process_recovery(
    filesystem, monkeypatch,
):
    stage(filesystem, snapshot(count=1))
    _fd, state, include, catalog, _events = filesystem
    actual = native._reload_native

    def abrupt_exit(distribution):
        raise KeyboardInterrupt("simulated abrupt process exit")

    monkeypatch.setattr(native, "_reload_native", abrupt_exit)
    with pytest.raises(KeyboardInterrupt):
        apply(filesystem)
    assert (state / native._WAL).is_file()
    assert include.is_file()
    assert (state / V2_STATE).is_file()
    assert not catalog.exists()
    monkeypatch.setattr(native, "_reload_native", actual)
    # simulate a separate invocation using the persisted WAL, NOT a
    # Python exception unwind rollback.
    assert recover(filesystem)["status"] == "NATIVE_V2_ROLLED_BACK"
    assert not include.exists()
    assert not (state / V2_STATE).exists()
    assert not catalog.exists()
    assert_no_pending(filesystem)


def test_same_version_repair_preserves_prior_catalog_and_rolls_back(
    filesystem, monkeypatch,
):
    first = snapshot(count=1)
    stage(filesystem, first)
    apply(filesystem)
    _fd, state, include, catalog, events = filesystem
    old_bytes = [(state / V2_STATE).read_bytes(), include.read_bytes(),
                 catalog.read_bytes(), (state / native._MANIFEST).read_bytes()]
    second = snapshot(count=1, generation=2, previous=first)
    stage(filesystem, second, expected=1,
          prior=hashlib.sha256(old_bytes[0]).hexdigest())

    def fail_reload(_distribution):
        raise native.NativeV2TransactionError("SIMULATED_RELOAD_FAILURE")

    monkeypatch.setattr(native, "_reload_native", fail_reload)
    with pytest.raises(native.NativeV2TransactionError,
                       match="APPLY_FAILED_RECOVERY_REQUIRED"):
        apply(filesystem)
    assert (state / native._WAL).is_file()
    monkeypatch.setattr(native, "_reload_native", lambda *_: None)
    assert recover(filesystem)["status"] == "NATIVE_V2_ROLLED_BACK"
    assert [(state / V2_STATE).read_bytes(), include.read_bytes(),
            catalog.read_bytes(), (state / native._MANIFEST).read_bytes()] == old_bytes
    assert_no_pending(filesystem)


@pytest.mark.parametrize("unsafe", [
    "existing_include", "existing_catalog", "symlink_include",
    "group_writable_include", "hardlink_include",
])
def test_foreign_existing_path_not_adopted(filesystem, unsafe):
    stage(filesystem, snapshot(count=1))
    _fd, state, include, catalog, _events = filesystem
    if unsafe == "existing_include":
        include.write_bytes(b"foreign configured server")
        include.chmod(0o644)
    elif unsafe == "existing_catalog":
        catalog.write_bytes(b'{"schema":1}')
        catalog.chmod(0o644)
    elif unsafe == "symlink_include":
        include.symlink_to("/etc/passwd")
    elif unsafe == "group_writable_include":
        include.write_bytes(b"unsafe")
        include.chmod(0o664)
    else:
        include.write_bytes(b"unsafe")
        include.chmod(0o644)
        os.link(include, include.parent / "other")
    with pytest.raises(native.NativeV2TransactionError):
        apply(filesystem)
    assert not (state / native._WAL).exists()
    assert not (state / V2_STATE).exists()


def test_stale_candidate_replay_refused_with_no_mutation(filesystem):
    stage(filesystem, snapshot(count=1))
    apply(filesystem)
    _fd, state, _include, _catalog, _events = filesystem
    before = (state / V2_STATE).read_bytes()
    with pytest.raises(native.NativeV2TransactionError, match="STATE_STALE"):
        apply(filesystem)
    assert (state / V2_STATE).read_bytes() == before
    assert_no_pending(filesystem)


def test_any_foreign_resource_change_while_wal_pending_blocks_recovery(
    filesystem, monkeypatch,
):
    stage(filesystem, snapshot(count=1))
    _fd, state, include, catalog, _events = filesystem
    monkeypatch.setattr(native, "_reload_native", lambda *_: (_ for _ in ()).throw(
        KeyboardInterrupt,
    ))
    with pytest.raises(KeyboardInterrupt):
        apply(filesystem)
    include.write_bytes(b"forged by unrelated host root")
    with pytest.raises(native.NativeV2TransactionError,
                       match="FOREIGN_RESOURCE_DRIFT"):
        recover(filesystem)
    assert (state / native._WAL).exists()


def test_unknown_root_operation_refused_without_io(filesystem):
    with pytest.raises(native.NativeV2TransactionError,
                       match="OPERATION_REFUSED"):
        native._operation_under_root(
            filesystem[0], distribution="debian", operation="LIST_FILES",
            fixture=True,
        )


def test_invalid_tls_pair_refused_before_first_wal_or_write(filesystem, monkeypatch):
    stage(filesystem, snapshot(count=1))
    _fd, state, include, catalog, events = filesystem
    def invalid(*args):
        raise native.NativeV2TransactionError("TLS_PAIR_INVALID")
    monkeypatch.setattr(native, "_verify_tls_pair", invalid)
    with pytest.raises(native.NativeV2TransactionError, match="TLS_PAIR_INVALID"):
        apply(filesystem)
    assert not (state / native._WAL).exists()
    assert not (state / V2_STATE).exists()
    assert not include.exists()
    assert not catalog.exists()


def test_catalog_validation_failure_retracts_publication(filesystem, monkeypatch):
    stage(filesystem, snapshot(count=1))
    _fd, state, include, catalog, events = filesystem
    seen = []
    def refuse_live_catalog(_doc, expected):
        seen.append(expected)
        assert catalog.read_bytes() == expected
        assert (state / native._WAL).is_file()
        raise native.NativeV2TransactionError("CATALOG_EXPOSURE_UNVERIFIED")
    monkeypatch.setattr(native, "_local_https_catalog", refuse_live_catalog)
    with pytest.raises(native.NativeV2TransactionError,
                       match="APPLY_FAILED_ROLLED_BACK"):
        apply(filesystem)
    assert len(seen) == 1
    assert not catalog.exists()
    assert not include.exists()
    assert not (state / V2_STATE).exists()
    assert_no_pending(filesystem)


def test_active_only_catalog_is_published_from_exact_managed_routes(
    filesystem, monkeypatch,
):
    config = document(2)
    config["repositories"][0]["desired_state"] = "active"
    stage(filesystem, snapshot(count=2, doc=config))
    monkeypatch.setattr(native, "_resolve_pins", lambda _doc: {
        "repo-0": {"mirror0.example.invalid": ["8.8.8.8"]},
    })
    result = apply(filesystem)
    _fd, state, include, catalog, events = filesystem
    assert result["status"] == "NATIVE_V2_COMMITTED"
    written = json.loads(catalog.read_text())
    assert written["schema"] == 1
    assert len(written["repositories"]) == 1
    assert written["repositories"][0]["upstream"] == (
        config["repositories"][0]["upstream"]["base_url"]
    )
    assert written["repositories"][0]["cache"].endswith(
        "/__repocache/repos/repo-0/"
    )
    nginx = include.read_text()
    assert "location ^~ /__repocache/repos/repo-0/" in nginx
    assert "location ^~ /__repocache/repos/repo-1/" not in nginx
    assert_no_pending(filesystem)


def test_private_dns_address_refused_before_durable_wal(filesystem, monkeypatch):
    config = document(1)
    config["repositories"][0]["desired_state"] = "active"
    stage(filesystem, snapshot(count=1, doc=config))
    monkeypatch.setattr(native, "_resolve_pins", lambda _doc: {
        "repo-0": {"mirror0.example.invalid": ["127.0.0.1"]},
    })
    with pytest.raises(native.NativeV2TransactionError, match="CANDIDATE_INVALID"):
        apply(filesystem)
    _fd, state, include, catalog, _events = filesystem
    assert not (state / native._WAL).exists()
    assert not include.exists()
    assert not catalog.exists()
