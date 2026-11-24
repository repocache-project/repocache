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
import socket
import tempfile
from pathlib import Path

import pytest

import repocache.server_native_v2_transaction_v1 as native
import repocache.server_native_root_control_entrypoint_v1 as dispatcher
import repocache.server_root_control_protocol_v1 as protocol
from repocache.server_protected_state_store_v1 import LOCK_NAME
from repocache.server_proposed_state_v2_store import V2_STATE
from repocache.server_root_control_fixed_candidate_v1 import _NAME
from test_server_proposed_state_v2_store import snapshot, document
from scripts import install_native_root_worker as installer

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
    # The real strict dump validator is also exercised during WAL recovery.
    # Derive the private fixture NGINX -T view from the actual restored
    # include, not from a no-op validator that could hide foreign drift.
    def fixture_nginx_dump():
        result = b"# configuration file /etc/nginx/nginx.conf:\nhttp {}\n"
        if include.exists():
            result += (b"# configuration file /etc/nginx/conf.d/"
                       b"repocache-managed.conf:\n" + include.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(native, "_capture_default_nginx_dump_private",
                        fixture_nginx_dump)
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


def reload_owned(fs):
    return native._operation_under_root(
        fs[0], distribution="debian", operation="RELOAD_V2", fixture=True,
    )


def assert_no_pending(fs):
    _, state, include, catalog, _events = fs
    assert not (state / native._WAL).exists()
    assert not (state / native._WAL_TMP).exists()
    assert not (state / native._STATE_STAGE).exists()
    assert not (state / native._MANIFEST_STAGE).exists()
    assert not (include.parent / native._STAGE).exists()
    assert not (catalog.parent / native._STAGE).exists()


@pytest.mark.parametrize("operation", ["APPLY_V2", "RELOAD_V2"])
def test_native_host_operation_requires_audited_package_completion(
    filesystem, monkeypatch, operation,
):
    from repocache.server_native_nginx_package_journal_v1 import NATIVE_COMPLETE_NAME
    _fd, state, include, catalog, events = filesystem

    def forbidden(*_a, **_kw):
        pytest.fail("unverified native package reached privileged service operation")

    monkeypatch.setattr(native, "_apply_locked", forbidden)
    monkeypatch.setattr(native, "_reload_owned_locked", forbidden)
    monkeypatch.setattr(native, "inspect_stock_nginx_package_file_integrity", forbidden)
    with pytest.raises(native.NativeV2TransactionError,
                       match="NATIVE_PACKAGE_COMPLETION_REQUIRED"):
        native._operation_under_root(
            filesystem[0], distribution="debian",
            operation=operation, fixture=False,
        )
    assert not (state / NATIVE_COMPLETE_NAME).exists()
    assert not include.exists() and not catalog.exists() and not events


@pytest.mark.parametrize("operation", ["APPLY_V2", "RELOAD_V2"])
def test_native_host_operation_refuses_stale_package_integrity_before_effects(
    filesystem, monkeypatch, operation,
):
    from repocache.server_native_nginx_package_journal_v1 import NATIVE_COMPLETE_NAME
    _fd, state, include, catalog, events = filesystem
    receipt = {
        "schema_version": 1,
        "status": "NATIVE_PACKAGE_EFFECTS_COMPLETED_AFTER_LOCKED_INSTALL",
        "distribution": "debian", "manager": "apt",
        "pending_sha256": "a" * 64, "vendor_unit_sha256": "b" * 64,
        "native_package_file_integrity_verified": True,
        "publisher_artifact_verified": False, "booted_native_service_verified": False,
    }
    candidate = state / NATIVE_COMPLETE_NAME
    candidate.write_bytes(_canon(receipt))
    candidate.chmod(0o600)

    def forbidden(*_a, **_kw):
        pytest.fail("stale package metadata reached privileged service operation")

    monkeypatch.setattr(native, "_apply_locked", forbidden)
    monkeypatch.setattr(native, "_reload_owned_locked", forbidden)
    monkeypatch.setattr(
        native, "inspect_stock_nginx_package_file_integrity",
        lambda: {
            "status": "READ_ONLY_STOCK_NGINX_PACKAGE_FILE_INTEGRITY_OBSERVED",
            "platform": "debian13",
            "native_package_file_integrity_verified": False,
            "native_package_signature_verified": False,
            "authorizes_native_marker_removal": False,
            "authorizes_nginx_activation": False,
        },
    )
    with pytest.raises(native.NativeV2TransactionError,
                       match="NATIVE_PACKAGE_INTEGRITY_CHANGED"):
        native._operation_under_root(
            filesystem[0], distribution="debian",
            operation=operation, fixture=False,
        )
    assert candidate.read_bytes() == _canon(receipt)
    assert not include.exists() and not catalog.exists() and not events


@pytest.mark.parametrize("operation", ["APPLY_V2", "RELOAD_V2"])
@pytest.mark.parametrize("unit_case", ["changed", "foreign", "matching"])
def test_native_host_package_receipt_pins_current_vendor_unit(
    filesystem, monkeypatch, operation, unit_case,
):
    from repocache.server_native_nginx_package_journal_v1 import NATIVE_COMPLETE_NAME
    _fd, state, include, catalog, events = filesystem
    receipt = {
        "schema_version": 1,
        "status": "NATIVE_PACKAGE_EFFECTS_COMPLETED_AFTER_LOCKED_INSTALL",
        "distribution": "debian", "manager": "apt",
        "pending_sha256": "a" * 64, "vendor_unit_sha256": "b" * 64,
        "native_package_file_integrity_verified": True,
        "publisher_artifact_verified": False, "booted_native_service_verified": False,
    }
    candidate = state / NATIVE_COMPLETE_NAME
    candidate.write_bytes(_canon(receipt))
    candidate.chmod(0o600)
    monkeypatch.setattr(native, "inspect_stock_nginx_package_file_integrity",
        lambda: {
            "status": "READ_ONLY_STOCK_NGINX_PACKAGE_FILE_INTEGRITY_OBSERVED",
            "platform": "debian13",
            "native_package_file_integrity_verified": True,
            "native_package_signature_verified": False,
            "authorizes_native_marker_removal": False,
            "authorizes_nginx_activation": False,
        },
    )
    from types import SimpleNamespace
    monkeypatch.setattr(native, "inspect_native_nginx_unit",
        lambda distribution: SimpleNamespace(to_dict=lambda: {
            "code": ("VENDOR_NGINX_SHADOW_REFUSED" if unit_case == "foreign"
                     else "VENDOR_NGINX_UNIT_OBSERVED"),
            "unit_name": "nginx.service",
            "vendor_unit_sha256": "c" * 64 if unit_case == "changed" else "b" * 64,
            "vendor_unit_bounded_and_owned": unit_case != "foreign",
            "authorizes_systemctl": False, "authorizes_nginx_reload": False,
        }),
    )
    called = []
    def reached(*_args, **_kwargs):
        called.append(operation)
        return {"status": "REACHED_AFTER_AUDIT"}
    monkeypatch.setattr(native, "_apply_locked", reached)
    monkeypatch.setattr(native, "_reload_owned_locked", reached)
    if unit_case == "matching":
        assert native._operation_under_root(
            filesystem[0], distribution="debian", operation=operation, fixture=False,
        )["status"] == "REACHED_AFTER_AUDIT"
        assert called == [operation]
    else:
        with pytest.raises(native.NativeV2TransactionError,
                           match="NATIVE_PACKAGE_UNIT_CHANGED"):
            native._operation_under_root(
                filesystem[0], distribution="debian", operation=operation, fixture=False,
            )
        assert not called
    assert candidate.read_bytes() == _canon(receipt)
    assert not include.exists() and not catalog.exists() and not events


@pytest.mark.parametrize("uid,groups,denial", [
    (65532, [49999], None),
    (65534, [49999], "SERVICE_IDENTITY_DENIED"),
    (65533, [], "ADMIN_GROUP_REQUIRED"),
])
def test_kernel_credentialed_dispatch_reaches_real_wal_only_for_admin(
    filesystem, monkeypatch, uid, groups, denial,
):
    stage(filesystem, snapshot(count=1))
    fd, state, include, catalog, events = filesystem
    monkeypatch.setattr(protocol, "_trusted_local_ids", lambda: (49999, 65534))
    monkeypatch.setattr(dispatcher, "_native_distro", lambda: "debian")
    monkeypatch.setattr(
        dispatcher, "execute_native_fixed_v2_transaction",
        lambda operation, distribution: native._operation_under_root(
            fd, distribution=distribution, operation=operation, fixture=True,
        ),
    )
    with tempfile.TemporaryDirectory(prefix="repocache-dispatch-") as base:
        os.chmod(base, 0o755)
        target = str(Path(base) / "control.sock")
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
            server.bind(target)
            # Let all fixture callers reach the actual kernel credential gate.
            # The installed unit adds its separate root:admin DAC checks.
            os.chmod(target, 0o666)
            server.listen(1)
            monkeypatch.setattr(dispatcher, "_systemd_listener", lambda: server)
            child = os.fork()
            if child == 0:
                try:
                    server.close()
                    os.close(fd)
                    os.setgroups(groups)
                    os.setgid(uid)
                    os.setuid(uid)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
                        client.settimeout(5)
                        client.connect(target)
                        client.sendall(b"apply-v2\n")
                        try:
                            packet = client.recv(1024)
                        except ConnectionResetError:
                            packet = b""
                        if denial is None:
                            assert json.loads(packet)["status"] == "APPLIED"
                        else:
                            assert packet == b""
                    os._exit(0)
                except BaseException:
                    os._exit(70)
            try:
                if denial is None:
                    assert dispatcher.serve_one_native_fixed_request()["status"] == "APPLIED"
                    assert ("reload", "debian") in events
                    assert all(path.is_file() for path in (state / V2_STATE, include, catalog))
                else:
                    with pytest.raises(protocol.FixedRootControlError, match=denial):
                        dispatcher.serve_one_native_fixed_request()
                    assert not events
                    assert not any(path.exists() for path in (state / V2_STATE, include, catalog))
            finally:
                ended, status = os.waitpid(child, 0)
                assert ended == child and os.waitstatus_to_exitcode(status) == 0
    assert_no_pending(filesystem)


def test_reviewed_proposal_is_staged_then_consumed_by_v2_worker(filesystem):
    fd, state, include, catalog, events = filesystem
    first = snapshot(count=1)
    raw = _canon(first)
    with pytest.raises(ValueError, match="PROPOSAL_PIN_MISMATCH"):
        installer._stage_proposal_under_root(fd, raw, "0" * 64)
    assert not (state / _NAME).exists()
    receipt = installer._stage_proposal_under_root(fd, raw, hashlib.sha256(raw).hexdigest())
    before = (state / _NAME).stat()
    assert receipt["expected_generation"] == 0
    assert not receipt["authorizes_service_activation"]
    assert not include.exists() and not catalog.exists() and not events
    installer._stage_proposal_under_root(fd, raw, receipt["proposed_state_sha256"])
    assert (state / _NAME).stat().st_ino == before.st_ino
    alternative = _canon(snapshot(count=2))
    with pytest.raises(ValueError, match="UNCOMMITTED_PRIOR_PROPOSAL"):
        installer._stage_proposal_under_root(fd, alternative, hashlib.sha256(alternative).hexdigest())
    assert (state / _NAME).stat().st_ino == before.st_ino

    apply(filesystem)
    assert (state / V2_STATE).read_bytes() == raw
    managed = [state / V2_STATE, state / _NAME, state / native._MANIFEST, include, catalog]
    before_repeat = [(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in managed]
    events.clear()
    repeated = installer._stage_proposal_under_root(fd, raw, receipt["proposed_state_sha256"])
    assert repeated["status"] == "AUTHENTICATED_V2_PROPOSAL_ALREADY_COMMITTED"
    assert apply(filesystem) == {"status": "NATIVE_V2_NO_CHANGE", "state_generation": 1}
    assert before_repeat == [(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in managed]
    assert ("reload", "debian") not in events and "syntax" not in events
    assert ("exposure", 1) in events
    assert any(isinstance(e, tuple) and e[0] == "catalog-exposure" for e in events)
    second = _canon(snapshot(count=1, generation=2, previous=first))
    assert installer._stage_proposal_under_root(
        fd, second, hashlib.sha256(second).hexdigest(),
    )["expected_generation"] == 1
    assert (state / V2_STATE).read_bytes() == raw


@pytest.mark.parametrize("lost", ["tls", "effective-include", "health", "catalog"])
def test_completed_proposal_noop_refuses_unverified_live_exposure(
    filesystem, monkeypatch, lost,
):
    stage(filesystem, snapshot(count=1))
    apply(filesystem)
    _fd, state, include, catalog, events = filesystem
    paths = (state / V2_STATE, state / _NAME, state / native._MANIFEST,
             include, catalog)
    before = [(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns)
              for p in paths]
    events.clear()

    def deny(*_args):
        raise native.NativeV2TransactionError("UNVERIFIED_" + lost.upper())

    if lost == "tls":
        monkeypatch.setattr(native, "_verify_tls_pair", deny)
    elif lost == "effective-include":
        monkeypatch.setattr(
            native, "_capture_default_nginx_dump_private",
            lambda: b"# configuration file /etc/nginx/nginx.conf:\nhttp {}\n",
        )
    elif lost == "health":
        monkeypatch.setattr(native, "_local_https_generation", deny)
    else:
        monkeypatch.setattr(native, "_local_https_catalog", deny)
    expected = "NGINX_DUMP_MISMATCH" if lost == "effective-include" else "UNVERIFIED_"
    with pytest.raises(native.NativeV2TransactionError, match=expected):
        apply(filesystem)
    assert ("reload", "debian") not in events
    assert "syntax" not in events
    assert [(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns)
            for p in paths] == before
    assert_no_pending(filesystem)


@pytest.mark.parametrize("drift", ["include", "catalog", "manifest", "pending", "generation"])
def test_completed_proposal_retry_refuses_drift(filesystem, drift):
    stage(filesystem, snapshot(count=1))
    apply(filesystem)
    _fd, state, include, catalog, events = filesystem
    committed = (state / V2_STATE).read_bytes()
    if drift == "pending":
        pending = state / native._WAL_TMP
        pending.write_bytes(b"interrupted")
        pending.chmod(0o600)
    elif drift == "generation":
        stage(filesystem, snapshot(count=1), expected=1, prior=hashlib.sha256(committed).hexdigest())
    else:
        target = {"include": include, "catalog": catalog, "manifest": state / native._MANIFEST}[drift]
        target.write_bytes(target.read_bytes() + b"\n")
    events.clear()
    with pytest.raises(ValueError):
        apply(filesystem)
    assert (state / V2_STATE).read_bytes() == committed
    assert not events


def test_prepared_partial_repair_preserves_omitted_repositories_and_retries(filesystem):
    stage(filesystem, snapshot(count=2))
    apply(filesystem)
    fd, state, include, catalog, events = filesystem
    prior_raw = (state / V2_STATE).read_bytes()
    prior_sha = hashlib.sha256(prior_raw).hexdigest()
    partial = document(count=1, generation=1)
    partial["deployment"]["cache_policy"]["global"]["inactive_seconds"] += 1
    raw = installer._repair_proposal(_canon(partial), prior_raw, prior_sha, "e" * 64)
    proposed = json.loads(raw)
    assert len(proposed["repository_records"]) == 2
    assert proposed["state_generation"] == 2
    assert proposed["approval_reference"]["decision_sha256"] == "e" * 64
    proposal_sha = hashlib.sha256(raw).hexdigest()
    pending = (state / _NAME).read_bytes()
    with pytest.raises(ValueError, match="PREVIOUS_STATE_PIN_MISMATCH"):
        installer._stage_proposal_under_root(
            fd, raw, proposal_sha, expected_state_sha256="0" * 64,
        )
    assert (state / _NAME).read_bytes() == pending
    installer._stage_proposal_under_root(
        fd, raw, proposal_sha, expected_state_sha256=prior_sha,
    )
    assert apply(filesystem)["state_generation"] == 2
    before = [(p.read_bytes(), p.stat().st_ino) for p in (state / V2_STATE, include, catalog)]
    events.clear()
    assert installer._stage_proposal_under_root(
        fd, raw, proposal_sha, expected_state_sha256=prior_sha,
    )["status"] == "AUTHENTICATED_V2_PROPOSAL_ALREADY_COMMITTED"
    assert installer._stage_proposal_under_root(
        fd, raw, proposal_sha, expected_state_sha256=proposal_sha,
    )["status"] == "AUTHENTICATED_V2_PROPOSAL_ALREADY_COMMITTED"
    with pytest.raises(ValueError, match="PREVIOUS_STATE_PIN_MISMATCH"):
        installer._stage_proposal_under_root(
            fd, raw, proposal_sha, expected_state_sha256="0" * 64,
        )
    assert apply(filesystem)["status"] == "NATIVE_V2_NO_CHANGE"
    assert before == [(p.read_bytes(), p.stat().st_ino) for p in (state / V2_STATE, include, catalog)]
    assert ("reload", "debian") not in events and "syntax" not in events
    assert ("exposure", 2) in events


def test_completed_proposal_retry_refuses_changed_intake(filesystem, monkeypatch):
    stage(filesystem, snapshot(count=1))
    apply(filesystem)
    _fd, state, include, catalog, events = filesystem
    original = native._load_private_under_root
    calls = []
    before = [(p.read_bytes(), p.stat().st_ino) for p in (state / V2_STATE, include, catalog)]

    def changed(*args, **kwargs):
        report, raw = original(*args, **kwargs)
        calls.append(None)
        if len(calls) == 2:
            report = {**report, "next_state_sha256": "f" * 64}
        return report, raw

    monkeypatch.setattr(native, "_load_private_under_root", changed)
    events.clear()
    with pytest.raises(native.NativeV2TransactionError, match="CANDIDATE_CHANGED"):
        apply(filesystem)
    assert len(calls) == 2
    assert before == [(p.read_bytes(), p.stat().st_ino) for p in (state / V2_STATE, include, catalog)]
    assert not events


@pytest.mark.parametrize("complete", [True, False])
def test_reviewed_proposal_handles_interrupted_staging(filesystem, complete):
    fd, state, include, catalog, events = filesystem
    raw = _canon(snapshot(count=1))
    digest = hashlib.sha256(raw).hexdigest()
    installer._stage_proposal_under_root(fd, raw, digest)
    envelope = (state / _NAME).read_bytes()
    interrupted = state / installer._PROPOSAL_STAGE
    interrupted.write_bytes(envelope if complete else envelope[:-1])
    interrupted.chmod(0o600)
    (state / _NAME).unlink()
    if complete:
        installer._stage_proposal_under_root(fd, raw, digest)
        assert (state / _NAME).read_bytes() == envelope
        assert not interrupted.exists()
    else:
        with pytest.raises(ValueError, match="FOREIGN_PROPOSAL_STAGE"):
            installer._stage_proposal_under_root(fd, raw, digest)
        assert interrupted.read_bytes() == envelope[:-1]
        assert not (state / _NAME).exists()
    assert not include.exists() and not catalog.exists() and not events


def test_reviewed_proposal_refuses_unreconciled_native_package_effects(filesystem):
    from repocache.server_native_nginx_package_journal_v1 import NATIVE_PENDING_NAME

    fd, state, include, catalog, events = filesystem
    marker = state / NATIVE_PENDING_NAME
    marker.write_bytes(b"native effects awaiting reconciliation")
    marker.chmod(0o600)
    raw = _canon(snapshot(count=1))
    with pytest.raises(ValueError, match="NATIVE_PACKAGE"):
        installer._stage_proposal_under_root(fd, raw, hashlib.sha256(raw).hexdigest())
    assert marker.read_bytes() == b"native effects awaiting reconciliation"
    assert not (state / _NAME).exists()
    assert not include.exists() and not catalog.exists() and not events


def test_live_inactive_nginx_refused_before_any_persistent_wal_or_include(
    filesystem, monkeypatch,
):
    # This is an isolated root-FD transaction, not a production service call.
    # The native package audit has already been exercised separately; test
    # that a clean but intentionally inactive nginx.service cannot cause
    # partial v2 state, a WAL or a compensating reload.
    stage(filesystem, snapshot(count=1))
    fd, state, include, catalog, events = filesystem
    proposal = state / _NAME
    before = proposal.read_bytes()

    monkeypatch.setattr(
        native, "_require_audited_native_package_for_activation",
        lambda *_args, **_kwargs: None,
    )
    def inactive(_distribution):
        native._deny("NGINX_NOT_ACTIVE_BEFORE_WAL")
    monkeypatch.setattr(native, "_require_active_nginx_before_wal", inactive)

    with pytest.raises(
        native.NativeV2TransactionError,
        match="^NATIVE_V2_NGINX_NOT_ACTIVE_BEFORE_WAL$",
    ):
        native._operation_under_root(
            fd, distribution="debian", operation="APPLY_V2", fixture=False,
        )
    assert proposal.read_bytes() == before
    assert not (state / V2_STATE).exists()
    assert not include.exists() and not catalog.exists()
    assert not (state / native._MANIFEST).exists()
    assert_no_pending(filesystem)
    assert all(not isinstance(event, tuple) or event[0] != "reload"
               for event in events)


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
    assert events == ["tls", "syntax", "dump", ("reload", "debian"),
                      ("exposure", 1), "dump",
                      ("catalog-exposure", len(catalog.read_bytes()))]
    assert (state / V2_STATE).is_file()
    assert include.stat().st_mode & 0o777 == 0o644
    assert catalog.stat().st_mode & 0o777 == 0o644
    assert json.loads(catalog.read_text()) == {"schema": 1, "repositories": []}
    assert (state / native._MANIFEST).is_file()
    assert recover(filesystem)["status"] == "NATIVE_V2_CLEAN"
    assert_no_pending(filesystem)


def test_apply_foreign_managed_context_refused_before_candidate_reload(
    filesystem, monkeypatch,
):
    """A bad candidate nginx -T may trigger old-generation rollback only."""
    initial = snapshot(count=1)
    stage(filesystem, initial)
    apply(filesystem)
    _fd, state, include, catalog, events = filesystem
    before = [(path.read_bytes(), path.stat().st_ino)
              for path in (state / V2_STATE, include, catalog, state / native._MANIFEST)]
    updated = snapshot(count=1, generation=2, previous=initial)
    stage(filesystem, updated, expected=1,
          prior=hashlib.sha256(before[0][0]).hexdigest())
    events.clear()
    observed_reload_includes = []
    actual_reload = native._reload_native

    def observe_reload(distribution):
        observed_reload_includes.append(include.read_bytes())
        return actual_reload(distribution)

    def refuse_foreign_dump(*_args):
        raise native.NativeV2TransactionError("NGINX_DUMP_MISMATCH")

    monkeypatch.setattr(native, "_reload_native", observe_reload)
    monkeypatch.setattr(native, "_route_dump_check", refuse_foreign_dump)
    with pytest.raises(native.NativeV2TransactionError,
                       match="APPLY_FAILED_ROLLED_BACK"):
        apply(filesystem)
    # A failed pre-reload check may need a compensating old-generation
    # systemd reload, but must NEVER reload the rejected candidate.
    assert observed_reload_includes == [before[1][0]]
    assert events.count(("reload", "debian")) == 1
    assert ("exposure", 2) not in events
    # Atomic WAL compensation may replace inodes, but must restore exactly
    # the previous published state, NGINX include, catalog and manifest bytes.
    assert [path.read_bytes()
            for path in (state / V2_STATE, include, catalog, state / native._MANIFEST)] == [
                content for content, _inode in before
            ]
    assert_no_pending(filesystem)


@pytest.mark.parametrize("failure", [None, "invalid-syntax", "reload-timeout", "foreign-dump"])
def test_managed_reload_keeps_committed_files_and_checks_exact_context(
    filesystem, monkeypatch, failure,
):
    stage(filesystem, snapshot(count=1))
    apply(filesystem)
    _fd, state, include, catalog, events = filesystem
    paths = (state / V2_STATE, include, catalog, state / native._MANIFEST)
    previous = [(path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                for path in paths]
    events.clear()
    managed_bytes = previous[1][0] if failure != "foreign-dump" else b"# unrelated\n"
    monkeypatch.setattr(native, "_capture_default_nginx_dump_private", lambda: (
        b"# configuration file /etc/nginx/nginx.conf:\nhttp {}\n\n"
        b"# configuration file /etc/nginx/conf.d/repocache-managed.conf:\n" + managed_bytes + b"\n"
    ))

    def refuse(*_args):
        raise native.NativeV2TransactionError(failure)

    if failure == "invalid-syntax":
        monkeypatch.setattr(native, "_native_syntax_check", refuse)
    if failure == "reload-timeout":
        monkeypatch.setattr(native, "_reload_native", refuse)
    if failure:
        expected = "NGINX_DUMP_MISMATCH" if failure == "foreign-dump" else failure
        with pytest.raises(native.NativeV2TransactionError, match=expected):
            reload_owned(filesystem)
        assert ("reload", "debian") not in events
    else:
        assert reload_owned(filesystem) == {
            "status": "NATIVE_V2_RELOADED", "state_generation": 1,
        }
        assert events.count(("reload", "debian")) == 1
        assert events.count(("exposure", 1)) == 2
        assert events.index("syntax") < events.index(("reload", "debian"))
    assert [(path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
            for path in paths] == previous
    assert_no_pending(filesystem)


def test_managed_reload_refuses_foreign_effective_include_after_reload(
    filesystem, monkeypatch,
):
    stage(filesystem, snapshot(count=1))
    apply(filesystem)
    _fd, state, include, catalog, events = filesystem
    paths = (state / V2_STATE, include, catalog, state / native._MANIFEST)
    before = [(path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
              for path in paths]
    events.clear()
    snapshots = iter((
        b"# configuration file /etc/nginx/conf.d/repocache-managed.conf:\n"
        + include.read_bytes() + b"\n",
        b"# configuration file /etc/nginx/conf.d/repocache-managed.conf:\n"
        b"# foreign post-reload include\n",
    ))
    monkeypatch.setattr(
        native, "_capture_default_nginx_dump_private",
        lambda: b"# configuration file /etc/nginx/nginx.conf:\nhttp {}\n"
                + next(snapshots),
    )
    with pytest.raises(native.NativeV2TransactionError, match="NGINX_DUMP_MISMATCH"):
        reload_owned(filesystem)
    assert events.count(("reload", "debian")) == 1
    assert events.count(("exposure", 1)) == 2
    assert [(path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
            for path in paths] == before
    assert_no_pending(filesystem)


def test_reload_refuses_unmanaged_state_without_any_native_effect(filesystem):
    with pytest.raises(native.NativeV2TransactionError, match="MANAGED_GENERATION_REQUIRED"):
        reload_owned(filesystem)
    assert not filesystem[-1]
    assert_no_pending(filesystem)


def test_native_v2_uses_the_existing_strict_tls_renderer(filesystem):
    """Installed candidate may not silently drop required TLS directives."""
    stage(filesystem, snapshot(count=1))
    assert apply(filesystem)["status"] == "NATIVE_V2_COMMITTED"
    include = filesystem[2].read_bytes()
    assert include.count(b"listen 127.0.0.1:443 ssl;") == 1
    assert include.count(b"ssl_certificate_key ") == 1
    assert include.count(b"ssl_protocols TLSv1.2 TLSv1.3;") == 1
    assert include.count(b"ssl_session_tickets off;") == 1
    assert include.count(b"server_tokens off;") == 1
    assert b"X-Repocache-Generation" in include
    assert b"/.well-known/repocache/catalog.json" in include
    assert_no_pending(filesystem)


def test_native_v2_refuses_untrusted_tls_renderer_authority(filesystem, monkeypatch):
    """No WAL, live include or catalog on a contradictory TLS authority."""
    stage(filesystem, snapshot(count=1))
    monkeypatch.setattr(native, "render_native_tls_listener_candidate",
                        lambda _doc: {
                            "status": "NATIVE_TLS_LISTENER_CANDIDATE_ONLY",
                            "authorizes_nginx_activation": True,
                            "authorizes_firewall_change": False,
                            "server_context_fragment": "server_tokens off;\n",
                        })
    with pytest.raises(native.NativeV2TransactionError,
                       match="NATIVE_V2_NGINX_TLS_CANDIDATE_UNTRUSTED"):
        apply(filesystem)
    assert not filesystem[2].exists()
    assert not filesystem[3].exists()
    assert not (filesystem[1] / V2_STATE).exists()
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
    first = snapshot(count=1)
    staged = stage(filesystem, first)
    stale_request = staged.read_bytes()
    apply(filesystem)
    _fd, state, _include, _catalog, events = filesystem
    prior = hashlib.sha256((state / V2_STATE).read_bytes()).hexdigest()
    stage(filesystem, snapshot(count=1, generation=2, previous=first), expected=1, prior=prior)
    apply(filesystem)
    before = (state / V2_STATE).read_bytes()
    staged.write_bytes(stale_request)
    events.clear()
    with pytest.raises(native.NativeV2TransactionError, match="STATE_STALE"):
        apply(filesystem)
    assert (state / V2_STATE).read_bytes() == before
    assert not events
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


@pytest.mark.skipif(not hasattr(os, "fork"), reason="Linux fork required")
def test_real_child_process_abrupt_exit_recovers_persistent_native_wal(
    filesystem, monkeypatch,
):
    """No Python exception unwinding: child dies after fsynced WAL + state."""
    stage(filesystem, snapshot(count=1))
    _fd, state, include, catalog, _events = filesystem
    original_reload = native._reload_native
    child = os.fork()
    if child == 0:
        # This branch never returns; the parent alone owns pytest results.
        native._reload_native = lambda *_args: os._exit(71)
        try:
            apply(filesystem)
        except BaseException:
            os._exit(72)
        os._exit(73)
    pid, result = os.waitpid(child, 0)
    assert pid == child and os.WIFEXITED(result)
    assert os.WEXITSTATUS(result) == 71
    assert (state / native._WAL).is_file()
    assert (state / V2_STATE).is_file()
    assert include.is_file()
    assert not catalog.exists()
    monkeypatch.setattr(native, "_reload_native", original_reload)
    assert recover(filesystem)["status"] == "NATIVE_V2_ROLLED_BACK"
    assert not include.exists()
    assert not catalog.exists()
    assert not (state / V2_STATE).exists()
    assert_no_pending(filesystem)


def test_no_wal_cannot_clear_unowned_orphan_stage(filesystem):
    _fd, state, include, catalog, _events = filesystem
    stage_file = include.parent / native._STAGE
    stage_file.write_bytes(b"orphan")
    stage_file.chmod(0o644)
    with pytest.raises(native.NativeV2TransactionError, match="ORPHAN_STAGE"):
        recover(filesystem)
    assert stage_file.read_bytes() == b"orphan"


def test_owner_manifest_cannot_hide_unauthorized_catalog_mapping(filesystem):
    stage(filesystem, snapshot(count=1))
    apply(filesystem)
    _fd, state, include, catalog, _events = filesystem
    unauthorized = _canon({
        "schema": 1,
        "repositories": [{
            "upstream": "https://foreign.example.invalid/",
            "cache": "https://cache.example.invalid/__repocache/repos/foreign/",
        }],
    })
    catalog.write_bytes(unauthorized)
    catalog.chmod(0o644)
    forged_manifest = native._manifest_for(
        (state / V2_STATE).read_bytes(), include.read_bytes(), unauthorized,
    )
    (state / native._MANIFEST).write_bytes(forged_manifest)
    (state / native._MANIFEST).chmod(0o600)
    with pytest.raises(native.NativeV2TransactionError, match="CATALOG_DRIFT"):
        recover(filesystem)


@pytest.mark.parametrize("active", [False, True])
def test_generated_complete_managed_nginx_server_passes_real_distro_parser(
    filesystem, monkeypatch, tmp_path, active,
):
    """Genuine nginx -t; NEVER reload the runner's installed NGINX service."""
    import shutil
    import subprocess
    from repocache.server_nginx_repository_bundle_v1 import (
        render_repository_nginx_bundle_candidate,
    )

    nginx = shutil.which("nginx")
    openssl = shutil.which("openssl")
    if nginx is None or openssl is None:
        pytest.skip("native nginx/openssl unavailable in this environment")
    ca = next((
        path for path in (
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ) if Path(path).is_file()
    ), None)
    if ca is None:
        pytest.skip("native distro CA bundle unavailable")
    key = tmp_path / "private.key"
    certificate = tmp_path / "certificate.pem"
    proc = subprocess.run(
        [openssl, "req", "-x509", "-nodes", "-newkey", "rsa:2048",
         "-sha256", "-days", "1", "-subj", "/CN=cache.example.invalid",
         "-keyout", str(key), "-out", str(certificate)],
        shell=False, check=False, capture_output=True, timeout=20,
    )
    if proc.returncode:
        pytest.fail("disposable test certificate creation failed")
    key.chmod(0o600)
    cfg = document(1)
    cfg["expected_state_generation"] = 1
    cfg["deployment"]["tls"]["certificate_file"] = str(certificate)
    cfg["deployment"]["tls"]["private_key_file"] = str(key)
    cfg["deployment"]["paths"]["cache_root"] = str(tmp_path / "cache")
    (tmp_path / "cache").mkdir(mode=0o700)
    cfg["repositories"][0]["desired_state"] = (
        "active" if active else "disabled"
    )
    pins = ({
        "repo-0": {"mirror0.example.invalid": ["8.8.8.8"]},
    } if active else {})
    bundle = render_repository_nginx_bundle_candidate(
        cfg, expected_state_generation=1,
        candidate_pins_by_repository=pins, ca_bundle_path=ca,
    )
    source, catalog, *_ = native._render_using_pins(
        cfg, 1, "debian" if "ca-certificates" in ca else "almalinux",
        pins, bundle,
    )
    if active:
        assert b"location ^~ /__repocache/repos/repo-0/" in source
        (tmp_path / "cache/repo-0").mkdir(mode=0o700)
    else:
        assert b"location ^~ /__repocache/repos/repo-0/" not in source
    assert b"X-Repocache-Generation" in source
    assert b"/.well-known/repocache/catalog.json" in source
    candidate = tmp_path / "repocache-managed.conf"
    candidate.write_bytes(source)
    (tmp_path / "logs").mkdir(mode=0o700)
    config = tmp_path / "nginx.conf"
    config.write_text(
        f"pid {tmp_path / 'nginx.pid'};\n"
        f"error_log {tmp_path / 'logs/error.log'} notice;\n"
        "events {}\n"
        "http {\n"
        "  access_log off;\n"
        f"  include {candidate};\n"
        "}\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [nginx, "-t", "-c", str(config), "-p", str(tmp_path)],
        shell=False, check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
    )
    assert completed.returncode == 0, (
        "generated managed NGINX server rejected by distro parser"
    )
    observed_catalog = json.loads(catalog)
    assert len(observed_catalog["repositories"]) == int(active)

    # The new dedicated context must also pass the real distro parser.
    # Substitute ONLY the fixed include and runtime PID paths with private
    # disposable fixture paths; never write the live /etc/nginx directory.
    cfg["deployment"]["paths"]["generated_include"] = native._OWNED_INCLUDE_PATH
    distro = "debian" if "ca-certificates" in ca else "almalinux"
    main, owned_include, owned_catalog = native._render_owned_managed_candidate(
        cfg, 1, distro, pins,
    )
    assert owned_include == source and owned_catalog == catalog
    owned_config = tmp_path / "repocache.conf"
    own_pid = str(tmp_path / "owned-nginx.pid").encode("ascii")
    fixture_main = main.replace(b"/run/repocache-nginx/nginx.pid", own_pid).replace(
        native._OWNED_INCLUDE_PATH.encode("ascii"), str(candidate).encode("ascii"),
    )
    owned_config.write_bytes(fixture_main)
    completed = subprocess.run(
        [nginx, "-T", "-c", str(owned_config), "-p", str(tmp_path)],
        shell=False, check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
    )
    assert completed.returncode == 0, "dedicated managed NGINX context rejected"
    # Normalize the two test-only paths back to the production constants
    # before exercising exact complete-context comparison.
    normalized = completed.stdout.replace(
        b"# configuration file " + str(owned_config).encode("ascii") + b":",
        b"# configuration file " + native._OWNED_MAIN_PATH.encode("ascii") + b":",
    ).replace(str(candidate).encode("ascii"), native._OWNED_INCLUDE_PATH.encode("ascii")
    ).replace(own_pid, b"/run/repocache-nginx/nginx.pid")
    native._verify_owned_context_dump(normalized, owned_include)


@pytest.mark.parametrize("resource", ["public_include", "private_state"])
def test_interrupted_partial_stage_is_recoverable_without_unsafe_publication(
    filesystem, monkeypatch, resource,
):
    """Crash after durable WAL but inside stage write, not after its fsync."""
    stage(filesystem, snapshot(count=1))
    _fd, state, include, catalog, events = filesystem
    if resource == "public_include":
        original = native._write_public
        def torn_public(parent, name, before, after, maximum):
            if name != native._INCLUDE:
                return original(parent, name, before, after, maximum)
            fd = os.open(native._STAGE, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                         0o600, dir_fd=parent)
            try:
                os.write(fd, b"partial config")
                os.fsync(fd)
            finally:
                os.close(fd)
            raise KeyboardInterrupt("simulated power loss during include write")
        monkeypatch.setattr(native, "_write_public", torn_public)
    else:
        original = native._write_private
        def torn_private(parent, name, temp, before, after, maximum):
            if name != V2_STATE:
                return original(parent, name, temp, before, after, maximum)
            fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                         0o600, dir_fd=parent)
            try:
                os.write(fd, b"partial state")
                os.fsync(fd)
            finally:
                os.close(fd)
            raise KeyboardInterrupt("simulated power loss during state write")
        monkeypatch.setattr(native, "_write_private", torn_private)
    with pytest.raises(KeyboardInterrupt):
        apply(filesystem)
    assert (state / native._WAL).is_file()
    if resource == "public_include":
        assert (include.parent / native._STAGE).stat().st_mode & 0o777 == 0o600
        monkeypatch.setattr(native, "_write_public", original)
    else:
        assert (state / native._STATE_STAGE).stat().st_mode & 0o777 == 0o600
        monkeypatch.setattr(native, "_write_private", original)
    assert recover(filesystem)["status"] == "NATIVE_V2_ROLLED_BACK"
    assert not (state / V2_STATE).exists()
    assert not include.exists()
    assert not catalog.exists()
    assert_no_pending(filesystem)


def test_torn_unpublished_wal_tmp_is_safe_to_discard_only_without_mutation(
    filesystem,
):
    _fd, state, include, catalog, _ = filesystem
    temp = state / native._WAL_TMP
    temp.write_bytes(b'{"version":1,"old_base64":')
    temp.chmod(0o600)
    result = recover(filesystem)
    assert result["status"] == "NATIVE_V2_UNPUBLISHED_WAL_DISCARDED"
    assert not temp.exists()
    assert not include.exists()
    assert not catalog.exists()
    assert not (state / V2_STATE).exists()
    assert_no_pending(filesystem)


def test_foreign_completed_public_stage_not_deleted_even_with_valid_wal(
    filesystem, monkeypatch,
):
    stage(filesystem, snapshot(count=1))
    _fd, state, include, catalog, _ = filesystem
    original = native._write_public
    def forged_public(parent, name, before, after, maximum):
        if name != native._INCLUDE:
            return original(parent, name, before, after, maximum)
        fd = os.open(native._STAGE, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                     0o600, dir_fd=parent)
        try:
            os.write(fd, b"foreign complete stage")
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        finally:
            os.close(fd)
        raise KeyboardInterrupt("simulated concurrent root-owned drift")
    monkeypatch.setattr(native, "_write_public", forged_public)
    with pytest.raises(KeyboardInterrupt):
        apply(filesystem)
    monkeypatch.setattr(native, "_write_public", original)
    with pytest.raises(native.NativeV2TransactionError, match="FOREIGN_STAGE"):
        recover(filesystem)
    assert (state / native._WAL).exists()
    assert (include.parent / native._STAGE).read_bytes() == b"foreign complete stage"


def test_rollback_retains_wal_until_restored_nginx_context_is_verified(
    filesystem, monkeypatch,
):
    """Keep a recoverable WAL when the old managed context is unprovable."""
    initial = snapshot(count=1)
    stage(filesystem, initial)
    apply(filesystem)
    _fd, state, include, catalog, _events = filesystem
    old = [(path, path.read_bytes()) for path in (
        state / V2_STATE, include, catalog, state / native._MANIFEST,
    )]
    stage(filesystem, snapshot(count=1, generation=2, previous=initial),
          expected=1, prior=hashlib.sha256(old[0][1]).hexdigest())
    actual_reload = native._reload_native

    def interrupted_reload(*_args):
        raise KeyboardInterrupt("test interruption after WAL and candidate write")

    monkeypatch.setattr(native, "_reload_native", interrupted_reload)
    with pytest.raises(KeyboardInterrupt):
        apply(filesystem)
    monkeypatch.setattr(native, "_reload_native", actual_reload)
    assert (state / native._WAL).is_file()
    ordinary_dump_check = native._verify_owned_include_in_dump

    def foreign_restored_dump(*_args, **_kwargs):
        raise native.NativeV2TransactionError("NGINX_DUMP_MISMATCH")

    monkeypatch.setattr(native, "_verify_owned_include_in_dump", foreign_restored_dump)
    with pytest.raises(native.NativeV2TransactionError,
                       match="NGINX_DUMP_MISMATCH"):
        recover(filesystem)
    assert (state / native._WAL).is_file()
    assert [path.read_bytes() for path, _raw in old] == [raw for _path, raw in old]
    monkeypatch.setattr(native, "_verify_owned_include_in_dump", ordinary_dump_check)
    assert recover(filesystem)["status"] == "NATIVE_V2_ROLLED_BACK"
    assert_no_pending(filesystem)


def test_native_dump_rollback_requires_managed_section_absent_for_initial_state():
    """A torn initial install is not recovered while its include is active."""
    ordinary = b"# configuration file /etc/nginx/nginx.conf:\nhttp {}\n"
    native._verify_owned_include_in_dump(None, captured_dump=ordinary)
    injected = ordinary + (
        b"# configuration file /etc/nginx/conf.d/repocache-managed.conf:\n"
        b"# foreign managed include\n"
    )
    with pytest.raises(native.NativeV2TransactionError,
                       match="NGINX_DUMP_MISMATCH"):
        native._verify_owned_include_in_dump(None, captured_dump=injected)


# #31/#64 strict live dump binding: catalog publication may never be
# authorized by a substring in a foreign file, duplicate include or comment.
_MANAGED_HEADER = b"# configuration file /etc/nginx/conf.d/repocache-managed.conf:\n"


def test_apply_route_dump_reuses_single_exact_managed_section(monkeypatch):
    include = b"# exact managed v2\nserver { listen 127.0.0.1:8443; }\n"
    expected_catalog = _canon({"schema": 1, "repositories": []})
    current = (
        b"nginx: configuration test is successful\n"
        b"# configuration file /etc/nginx/nginx.conf:\n"
        b"events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\n"
        + _MANAGED_HEADER + include + b"\n"
    )
    observations = []
    monkeypatch.setattr(native, "_capture_default_nginx_dump_private",
                        lambda: current)

    def parsed(_document, *, nginx_dump_text, **_kwargs):
        observations.append(nginx_dump_text.encode("utf-8"))
        return {"candidate_catalog": {"schema": 1, "repositories": []}}

    monkeypatch.setattr(native, "preview_derived_catalog_from_nginx_dump", parsed)
    native._route_dump_check({}, include, expected_catalog,
                             "debian", 2, {})
    assert observations == [current]


@pytest.mark.parametrize("substitution", [
    "missing",
    "wrong-filename",
    "fake-comment",
    "duplicate",
    "modified",
    "prefix-only",
])
def test_apply_route_dump_requires_unique_exact_owned_file(
    monkeypatch, substitution,
):
    include = b"# exact managed v2\nserver { listen 127.0.0.1:8443; }\n"
    managed = _MANAGED_HEADER + include
    foreign = b"# configuration file /etc/nginx/nginx.conf:\n"
    dumps = {
        "missing": foreign + b"events {}\n",
        "wrong-filename": (
            foreign + b"events {}\n"
            + b"# configuration file /etc/nginx/conf.d/foreign.conf:\n"
            + include
        ),
        "fake-comment": foreign + b"# " + include,
        "duplicate": foreign + b"events {}\n" + managed
                     + b"# configuration file /etc/nginx/conf.d/repocache-managed.conf:\n"
                     + include,
        "modified": foreign + b"events {}\n" + managed
                    + b"# foreign appended text in managed include\n",
        "prefix-only": foreign + b"events {}\n" + _MANAGED_HEADER
                       + include[:-1],
    }
    captured = dumps[substitution]
    monkeypatch.setattr(native, "_capture_default_nginx_dump_private",
                        lambda: captured)

    def should_not_derive(*_args, **_kwargs):
        pytest.fail("untrusted NGINX dump reached catalog derivation")

    monkeypatch.setattr(native, "preview_derived_catalog_from_nginx_dump",
                        should_not_derive)
    with pytest.raises(native.NativeV2TransactionError,
                       match="NGINX_DUMP_MISMATCH"):
        native._route_dump_check(
            {}, include, _canon({"schema": 1, "repositories": []}),
            "debian", 2, {},
        )


def test_apply_route_dump_refuses_unverified_derived_catalog(monkeypatch):
    include = b"# exact managed\n"
    monkeypatch.setattr(
        native, "_capture_default_nginx_dump_private",
        lambda: _MANAGED_HEADER + include,
    )
    monkeypatch.setattr(
        native, "preview_derived_catalog_from_nginx_dump",
        lambda *_args, **_kwargs: {
            "candidate_catalog": {"schema": 1, "repositories": [
                {"id": "forged"}
            ]}
        },
    )
    with pytest.raises(native.NativeV2TransactionError,
                       match="CATALOG_MISMATCH"):
        native._route_dump_check(
            {}, include, _canon({"schema": 1, "repositories": []}),
            "debian", 2, {},
        )


@pytest.mark.parametrize("resource", ["state", "include", "catalog", "manifest"])
@pytest.mark.parametrize("tamper", ["mode", "hardlink", "bytes"])
def test_completed_same_version_noop_rejects_protected_inode_and_metadata_drift(
    filesystem, resource, tamper,
):
    """A repeated install must neither adopt changed bytes nor repair foreign inodes."""
    stage(filesystem, snapshot(count=1))
    assert apply(filesystem)["state_generation"] == 1
    _fd, state, include, catalog, events = filesystem
    paths = {
        "state": state / V2_STATE,
        "include": include,
        "catalog": catalog,
        "manifest": state / native._MANIFEST,
    }
    original = {name: path.read_bytes() for name, path in paths.items()}
    target = paths[resource]
    extra = target.parent / (target.name + ".foreign-link")
    if tamper == "mode":
        target.chmod(0o666)
    elif tamper == "hardlink":
        os.link(target, extra)
    else:
        target.write_bytes(original[resource] + b"\nforeign drift")
    after_tamper = {name: path.read_bytes() for name, path in paths.items()}
    events.clear()
    with pytest.raises(ValueError):
        apply(filesystem)
    assert {name: path.read_bytes() for name, path in paths.items()} == after_tamper
    assert ("reload", "debian") not in events
    assert "syntax" not in events
    assert not (state / native._WAL).exists()
    if tamper == "hardlink":
        assert extra.is_file() and extra.stat().st_ino == target.stat().st_ino
    if tamper == "mode":
        assert target.stat().st_mode & 0o777 == 0o666


@pytest.mark.parametrize("operation", ["APPLY_V2", "RELOAD_V2", "RECOVER_V2"])
@pytest.mark.parametrize("marker_kind", ["valid", "malformed", "dangling"])
def test_owned_bootstrap_claim_blocks_all_legacy_vendor_operations(
    filesystem, monkeypatch, operation, marker_kind,
):
    fd, state, include, catalog, events = filesystem
    name = (installer._CONFIG_MARKER if marker_kind == "valid"
            else installer._CONFIG_MARKER_PREFIX + "unrecognized")
    marker = state / name
    if marker_kind == "dangling":
        marker.symlink_to("missing")
    else:
        marker.write_bytes(b"" if marker_kind == "valid" else b"foreign")
        marker.chmod(0o600)
    before = sorted(os.listdir(state))

    def forbidden(*_args, **_kwargs):
        pytest.fail("owned bootstrap claim reached legacy vendor effects")

    for name in ("_apply_locked", "_reload_owned_locked", "_recover_locked",
                 "_require_audited_native_package_for_activation"):
        monkeypatch.setattr(native, name, forbidden)
    with pytest.raises(native.NativeV2TransactionError,
                       match="OWNED_NGINX_TRANSITION_REQUIRED"):
        native._operation_under_root(fd, distribution="debian",
                                     operation=operation, fixture=False)
    assert sorted(os.listdir(state)) == before
    assert os.path.lexists(marker)
    assert not include.exists() and not catalog.exists() and not events
    assert not (state / native._WAL).exists()
    assert not (state / native._WAL_TMP).exists()


def test_owned_marker_scan_failure_refuses_legacy_vendor_mode(monkeypatch):
    def unavailable(_fd):
        raise PermissionError("private path must not be returned")
    monkeypatch.setattr(native.os, "listdir", unavailable)
    with pytest.raises(native.NativeV2TransactionError,
                       match="^NATIVE_V2_NGINX_OWNERSHIP_UNVERIFIED$"):
        native._refuse_legacy_vendor_mode_after_owned_claim(123)

def _owned_dump(include=None):
    main = (native._OWNED_BOOTSTRAP_CONFIG if include is None
            else native._OWNED_MANAGED_CONFIG)
    result = b"# configuration file /etc/nginx/repocache.conf:\n" + main + b"\n"
    if include is not None:
        result += (b"# configuration file /etc/nginx/repocache-managed.conf:\n"
                   + include + b"\n")
    return result


def test_owned_context_bootstrap_matches_signed_archive_source():
    source = (Path(__file__).resolve().parents[1]
              / "docs/examples/nginx/repocache.conf").read_bytes()
    assert native._OWNED_BOOTSTRAP_CONFIG == installer._BOOTSTRAP_CONFIG == source
    assert installer._CONFIG_MARKER.endswith(hashlib.sha256(source).hexdigest())
    assert b"listen 127.0.0.1:8008;" in source
    assert b"include " not in source.split(b"\npid ", 1)[1]
    native._verify_owned_context_dump(_owned_dump(), None)


@pytest.mark.parametrize("path", [
    "/etc/nginx/conf.d/repocache-managed.conf",
    "/etc/nginx/nginx.conf",
    "/tmp/repocache-managed.conf",
])
def test_owned_context_candidate_refuses_legacy_or_caller_selected_include(path):
    cfg = document(1)
    cfg["expected_state_generation"] = 1
    cfg["deployment"]["paths"]["generated_include"] = path
    with pytest.raises(native.NativeV2TransactionError,
                       match="OWNED_CONTEXT_LAYOUT_UNSUPPORTED"):
        native._render_owned_managed_candidate(cfg, 1, "debian", {})


@pytest.mark.parametrize("active", [False, True])
def test_owned_context_candidate_exact_complete_dump(active):
    cfg = document(1)
    cfg["expected_state_generation"] = 1
    cfg["deployment"]["paths"]["generated_include"] = native._OWNED_INCLUDE_PATH
    cfg["repositories"][0]["desired_state"] = "active" if active else "disabled"
    pins = {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}} if active else {}
    before = _canon(cfg)
    main, include, catalog = native._render_owned_managed_candidate(
        cfg, 1, "debian", pins,
    )
    assert main == native._OWNED_MANAGED_CONFIG
    assert b"include /etc/nginx/repocache-managed.conf;" in main
    assert b"conf.d" not in main and b"nginx.conf" not in main
    assert b"127.0.0.1:8008" not in main
    assert b'X-Repocache-Generation "1"' in include
    assert len(json.loads(catalog)["repositories"]) == int(active)
    assert _canon(cfg) == before
    native._verify_owned_context_dump(_owned_dump(include), include)


@pytest.mark.parametrize("tamper", [
    "foreign-main", "foreign-include", "duplicate", "extra-section",
    "altered-main", "altered-include", "missing-include", "wrong-order",
])
def test_owned_context_refuses_any_foreign_or_incomplete_section(tamper):
    include = b"# REPOCACHE managed v2\nserver { listen 443 ssl; }\n"
    dump = _owned_dump(include)
    section = b"# configuration file /etc/nginx/repocache-managed.conf:\n"
    if tamper == "foreign-main":
        dump = dump.replace(b"/etc/nginx/repocache.conf:", b"/etc/nginx/nginx.conf:")
    elif tamper == "foreign-include":
        dump = dump.replace(b"/etc/nginx/repocache-managed.conf:", b"/etc/nginx/conf.d/repocache-managed.conf:")
    elif tamper == "duplicate":
        dump += section + include + b"\n"
    elif tamper == "extra-section":
        dump += b"# configuration file /etc/nginx/foreign.conf:\n# foreign\n"
    elif tamper == "altered-main":
        dump = dump.replace(b"worker_processes 1;", b"worker_processes 2;")
    elif tamper == "altered-include":
        dump = dump.replace(b"listen 443", b"listen 444")
    elif tamper == "missing-include":
        dump = dump.split(section)[0]
    else:
        main, rest = dump.split(section)
        dump = section + rest + main
    with pytest.raises(native.NativeV2TransactionError,
                       match="OWNED_CONTEXT_DUMP_MISMATCH"):
        native._verify_owned_context_dump(dump, include)


def test_owned_context_bootstrap_never_accepts_managed_or_foreign_dump():
    with pytest.raises(native.NativeV2TransactionError,
                       match="OWNED_CONTEXT_DUMP_MISMATCH"):
        native._verify_owned_context_dump(
            _owned_dump(b"# REPOCACHE managed v2\nserver {}\n"), None,
        )
    with pytest.raises(native.NativeV2TransactionError,
                       match="OWNED_CONTEXT_DUMP_MISMATCH"):
        native._verify_owned_context_dump(
            _owned_dump() + b"# configuration file /etc/nginx/foreign.conf:\n# foreign\n",
            None,
        )

@pytest.mark.parametrize("managed", [False, True])
@pytest.mark.parametrize("fault", ["none", "missing-claim", "foreign-main",
                                  "foreign-include", "post-drift"])
def test_owned_context_native_probe_requires_exact_files_and_claim(
    tmp_path, monkeypatch, managed, fault,
):
    root = tmp_path / "root"
    root.mkdir(mode=0o755)
    directory = root / "etc/nginx"
    directory.mkdir(parents=True)
    state = root / "state"
    state.mkdir(mode=0o700)
    marker = state / installer._CONFIG_MARKER
    if fault != "missing-claim":
        marker.touch(mode=0o600)
    main = directory / "repocache.conf"
    main.write_bytes(native._OWNED_MANAGED_CONFIG if managed
                     else native._OWNED_BOOTSTRAP_CONFIG)
    main.chmod(0o644)
    expected = b"# REPOCACHE managed v2\nserver {}\n" if managed else None
    include = directory / "repocache-managed.conf"
    if expected is not None:
        include.write_bytes(expected)
        include.chmod(0o644)
    if fault == "foreign-main":
        main.write_bytes(b"foreign")
    if fault == "foreign-include":
        include.write_bytes(b"foreign")
        include.chmod(0o644)
    seen = []
    # Test the filesystem contract against a disposable root, never launch
    # a host command. Production refuses a non-current namespace root.
    monkeypatch.setattr(native, "_verify_current_root_fd", lambda _fd: None)

    def capture(*, managed):
        seen.append(managed)
        if fault == "post-drift":
            main.write_bytes(b"changed after native command")
        return _owned_dump(expected)

    monkeypatch.setattr(native, "_capture_owned_nginx_dump_private", capture)
    rfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    sfd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if fault == "none":
            assert native._probe_owned_context_locked(rfd, sfd, expected) == _owned_dump(expected)
            assert seen == [managed]
        else:
            with pytest.raises(native.NativeV2TransactionError, match="OWNED_CONTEXT_"):
                native._probe_owned_context_locked(rfd, sfd, expected)
            assert seen == ([managed] if fault == "post-drift" else [])
    finally:
        os.close(sfd)
        os.close(rfd)

def _owned_bootstrap_resources():
    return {
        V2_STATE: None, native._OWNED_MAIN: native._OWNED_BOOTSTRAP_CONFIG,
        native._INCLUDE: None, native._CATALOG: None,
        native._OWNED_MANIFEST: None,
    }


def _owned_generation(generation=1, previous=None):
    cfg = document(1, generation=generation)
    cfg["deployment"]["paths"]["generated_include"] = native._OWNED_INCLUDE_PATH
    cfg["repositories"][0]["desired_state"] = "active"
    state = _canon(snapshot(generation=generation, previous=previous, doc=cfg))
    main, include, catalog = native._render_owned_managed_candidate(
        cfg, generation, "debian",
        {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}},
    )
    return {
        V2_STATE: state, native._OWNED_MAIN: main, native._INCLUDE: include,
        native._CATALOG: catalog, native._OWNED_MANIFEST:
            native._owned_manifest_for(state, main, include, catalog),
    }


@pytest.mark.parametrize("initial", [True, False])
def test_owned_wal_round_trip_pins_exact_main_and_previous_generation(initial):
    old = _owned_bootstrap_resources() if initial else _owned_generation()
    previous = None if initial else json.loads(old[V2_STATE])
    new = _owned_generation(1 if initial else 2, previous=previous)
    raw = native._owned_wal_record(old, new)
    assert native._decode_owned_wal(raw) == (
        old, {name: native._hash(new[name]) for name in native._OWNED_ORDER},
    )
    parsed = json.loads(raw)
    assert parsed["service_domain"] == "repocache-nginx.service"
    assert parsed["old_sha256"][native._OWNED_MAIN] == native._hash(
        native._OWNED_BOOTSTRAP_CONFIG if initial else native._OWNED_MANAGED_CONFIG
    )
    for name in native._OWNED_ORDER:
        mixed = dict(old)
        mixed[name] = new[name]
        native._owned_wal_resource_drift(
            old, parsed["new_sha256"], mixed, unpublished=False,
        )
        if mixed != old:
            with pytest.raises(native.NativeV2TransactionError,
                               match="OWNED_WAL_UNPUBLISHED_DRIFT"):
                native._owned_wal_resource_drift(
                    old, parsed["new_sha256"], mixed, unpublished=True,
                )
        mixed[name] = b"foreign bytes"
        with pytest.raises(native.NativeV2TransactionError,
                           match="OWNED_WAL_FOREIGN_DRIFT"):
            native._owned_wal_resource_drift(
                old, parsed["new_sha256"], mixed, unpublished=False,
            )


@pytest.mark.parametrize("fault", ["version", "service", "old-main",
                                  "new-main", "missing-key", "extra-key"])
def test_owned_wal_refuses_wrong_domain_and_corrupt_records(fault):
    old = _owned_bootstrap_resources()
    record = json.loads(native._owned_wal_record(old, _owned_generation()))
    if fault == "version":
        record["version"] = 1
    elif fault == "service":
        record["service_domain"] = "nginx.service"
    elif fault == "old-main":
        record["old_base64"][native._OWNED_MAIN] = native._encode(b"foreign")
        record["old_sha256"][native._OWNED_MAIN] = native._hash(b"foreign")
    elif fault == "new-main":
        record["new_sha256"][native._OWNED_MAIN] = "a" * 64
    elif fault == "missing-key":
        del record["old_sha256"][native._OWNED_MAIN]
    else:
        record["new_sha256"]["nginx.conf"] = "a" * 64
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_"):
        native._decode_owned_wal(_canon(record))


def test_owned_wal_rejects_rehashed_legacy_manifest_and_stale_generation():
    new = _owned_generation()
    foreign = dict(new)
    foreign[native._OWNED_MANIFEST] = native._manifest_for(
        new[V2_STATE], new[native._INCLUDE], new[native._CATALOG],
    )
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_MANIFEST_DRIFT"):
        native._owned_wal_record(_owned_bootstrap_resources(), foreign)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_GENERATION_INVALID"):
        native._owned_wal_record(new, new)


def test_owned_wal_fixture_publication_preserves_all_previous_resources(filesystem):
    fd, state, vendor, catalog, events = filesystem
    marker = state / installer._CONFIG_MARKER
    marker.touch(mode=0o600)
    main = vendor.parent.parent / native._OWNED_MAIN
    main.write_bytes(native._OWNED_BOOTSTRAP_CONFIG)
    main.chmod(0o644)
    journal = native._publish_owned_wal_fixture(fd, _owned_generation())
    assert (state / native._OWNED_WAL).read_bytes() == journal
    assert not (state / native._OWNED_WAL_TMP).exists()
    assert (state / native._OWNED_WAL).stat().st_mode & 0o777 == 0o600
    assert native._decode_owned_wal(journal)[0] == _owned_bootstrap_resources()
    assert main.read_bytes() == native._OWNED_BOOTSTRAP_CONFIG
    assert not vendor.exists() and not catalog.exists() and not events
    assert not (main.parent / native._INCLUDE).exists()
    assert not (state / V2_STATE).exists()
    assert not (state / native._OWNED_MANIFEST).exists()
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_DOMAIN_REQUIRED"):
        native._publish_owned_wal_fixture(fd, _owned_generation())


@pytest.mark.parametrize("name", [native._OWNED_WAL, native._OWNED_WAL_TMP,
                                  native._OWNED_MANIFEST])
@pytest.mark.parametrize("operation", ["APPLY_V2", "RELOAD_V2", "RECOVER_V2"])
def test_owned_wal_artifacts_refuse_legacy_even_without_bootstrap_claim(
    filesystem, name, operation,
):
    fd, state, vendor, catalog, events = filesystem
    artifact = state / name
    artifact.symlink_to("missing")
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_DOMAIN_REQUIRED"):
        native._operation_under_root(fd, distribution="debian",
                                     operation=operation, fixture=True)
    assert artifact.is_symlink()
    assert not vendor.exists() and not catalog.exists() and not events


def test_owned_wal_fixture_refuses_actual_root_before_io():
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="CURRENT_NAMESPACE_ROOT_WRITES_REFUSED"):
            native._publish_owned_wal_fixture(fd, {})
    finally:
        os.close(fd)
