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
import stat
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
        (("etc", "nginx", "repocache.d"), 0o755),
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
    identity = ("a" * 64, 123)
    def fixture_reload(distribution):
        events.append(("reload", distribution))
        return identity
    monkeypatch.setattr(native, "_reload_native", fixture_reload)
    monkeypatch.setattr(native, "_native_reload_identity", lambda distro: identity)
    monkeypatch.setattr(native, "_local_https_generation",
                        lambda document, generation, **kw: events.append(
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

    def fail_once(*args, **kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise native.NativeV2TransactionError("SIMULATED_REFUSAL")
        return old(*args, **kwargs)

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
    monkeypatch.setattr(native, "_reload_native", lambda *_: ("a" * 64, 123))
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
    # Render the fixed production layout first, then substitute only the
    # include, runtime PID and cache paths in the disposable parser fixture.
    cfg["deployment"]["paths"]["generated_include"] = native._OWNED_INCLUDE_PATH
    fixed_cache = b"/var/cache/nginx/repocache-managed"
    fixture_cache = str(tmp_path / "cache").encode("ascii")
    cfg["deployment"]["paths"]["cache_root"] = fixed_cache.decode("ascii")
    cfg["deployment"]["paths"]["log_root"] = "/var/log/nginx/repocache-managed"
    distro = "debian" if "ca-certificates" in ca else "almalinux"
    main, owned_include, owned_catalog = native._render_owned_managed_candidate(
        cfg, 1, distro, pins,
    )
    assert owned_include.replace(fixed_cache, fixture_cache) == source
    assert owned_catalog == catalog
    owned_config = tmp_path / "repocache.conf"
    own_pid = str(tmp_path / "owned-nginx.pid").encode("ascii")
    fixture_main = main.replace(b"/run/repocache-nginx/nginx.pid", own_pid).replace(
        native._OWNED_INCLUDE_PATH.encode("ascii"), str(candidate).encode("ascii"),
    )
    # Redirect only the fixed scratch paths for this disposable parser.
    # The production path is exercised separately inside the confined VM.
    scratch_pairs = []
    scratch = tmp_path / "owned-runtime"
    scratch.mkdir(mode=0o755)
    for directive, leaf in native._OWNED_RUNTIME_TEMP_NAMES:
        fixed = f"/run/repocache-nginx/{leaf}".encode("ascii")
        fixture = str(scratch / leaf).encode("ascii")
        assert directive.encode("ascii") + b" " + fixed + b";" in fixture_main
        fixture_main = fixture_main.replace(fixed + b";", fixture + b";")
        scratch_pairs.append((fixture, fixed))
    owned_config.write_bytes(fixture_main)
    completed = subprocess.run(
        [nginx, "-T", "-c", str(owned_config), "-p", str(tmp_path)],
        shell=False, check=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
    )
    assert completed.returncode == 0, "dedicated managed NGINX context rejected"
    # Normalize the test-only paths back to the production constants
    # before exercising exact complete-context comparison.
    normalized = completed.stdout.replace(
        b"# configuration file " + str(owned_config).encode("ascii") + b":",
        b"# configuration file " + native._OWNED_MAIN_PATH.encode("ascii") + b":",
    ).replace(str(candidate).encode("ascii"), native._OWNED_INCLUDE_PATH.encode("ascii")
    ).replace(own_pid, b"/run/repocache-nginx/nginx.pid").replace(
        fixture_cache, fixed_cache,
    )
    for fixture, fixed in scratch_pairs:
        normalized = normalized.replace(fixture + b";", fixed + b";")
    native._verify_owned_context_dump(normalized, owned_include, managed_main=main)


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

def _owned_dump(include=None, *, distribution="debian"):
    main = (native._OWNED_BOOTSTRAP_CONFIG if include is None
            else native._owned_managed_config(distribution))
    result = b"# configuration file /etc/nginx/repocache.d/repocache.conf:\n" + main + b"\n"
    if include is not None:
        result += (b"# configuration file /etc/nginx/repocache.d/repocache-managed.conf:\n"
                   + include + b"\n")
    return result


def test_owned_context_bootstrap_matches_signed_archive_source():
    source = (Path(__file__).resolve().parents[1]
              / "docs/examples/nginx/repocache.conf").read_bytes()
    assert native._OWNED_BOOTSTRAP_CONFIG == installer._BOOTSTRAP_CONFIG == source
    assert installer._CONFIG_MARKER.endswith(hashlib.sha256(
        b"/etc/nginx/repocache.d/\0" + source).hexdigest())
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
    assert b"include /etc/nginx/repocache.d/repocache-managed.conf;" in main
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
    section = b"# configuration file /etc/nginx/repocache.d/repocache-managed.conf:\n"
    if tamper == "foreign-main":
        dump = dump.replace(b"/etc/nginx/repocache.d/repocache.conf:", b"/etc/nginx/nginx.conf:")
    elif tamper == "foreign-include":
        dump = dump.replace(b"/etc/nginx/repocache.d/repocache-managed.conf:", b"/etc/nginx/conf.d/repocache-managed.conf:")
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
    directory = root / "etc/nginx/repocache.d"
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
    monkeypatch.setattr(native, "_owned_debian_runtime_temps",
                        lambda *_args, **_kwargs: ((1,), {}))
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


def _owned_generation(generation=1, previous=None, *, active=True):
    cfg = document(1, generation=generation)
    cfg["deployment"]["paths"]["generated_include"] = native._OWNED_INCLUDE_PATH
    cfg["repositories"][0]["desired_state"] = "active" if active else "disabled"
    state = _canon(snapshot(generation=generation, previous=previous, doc=cfg))
    main, include, catalog = native._render_owned_managed_candidate(
        cfg, generation, "debian",
        {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}} if active else {},
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
    main = vendor.parent.parent / "repocache.d" / native._OWNED_MAIN
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
                                  native._OWNED_MANIFEST,
                                  native._OWNED_STAGES[V2_STATE],
                                  native._OWNED_STAGES[native._OWNED_MANIFEST]])
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

def test_owned_wal_fixture_accepts_exact_committed_generation(filesystem):
    fd, state, vendor, catalog, events = filesystem
    (state / installer._CONFIG_MARKER).touch(mode=0o600)
    old = _owned_generation()
    main = vendor.parent.parent / "repocache.d" / native._OWNED_MAIN
    include = main.parent / native._INCLUDE
    paths = {
        V2_STATE: state / V2_STATE, native._OWNED_MAIN: main,
        native._INCLUDE: include, native._CATALOG: catalog,
        native._OWNED_MANIFEST: state / native._OWNED_MANIFEST,
    }
    for name, path in paths.items():
        path.write_bytes(old[name])
        path.chmod(0o600 if name in (V2_STATE, native._OWNED_MANIFEST) else 0o644)
    new = _owned_generation(2, previous=json.loads(old[V2_STATE]))
    journal = native._publish_owned_wal_fixture(fd, new)
    assert native._decode_owned_wal(journal)[0] == old
    assert {name: path.read_bytes() for name, path in paths.items()} == old
    assert not vendor.exists() and not events


def test_owned_wal_fixture_interrupted_rename_preserves_temp_and_bootstrap(
    filesystem, monkeypatch,
):
    fd, state, vendor, catalog, events = filesystem
    (state / installer._CONFIG_MARKER).touch(mode=0o600)
    main = vendor.parent.parent / "repocache.d" / native._OWNED_MAIN
    main.write_bytes(native._OWNED_BOOTSTRAP_CONFIG)
    main.chmod(0o644)
    actual = os.replace

    def interrupted(src, dst, **kwargs):
        if src == native._OWNED_WAL_TMP and dst == native._OWNED_WAL:
            raise OSError("injected crash before publication")
        return actual(src, dst, **kwargs)

    monkeypatch.setattr(native.os, "replace", interrupted)
    with pytest.raises(OSError, match="injected crash"):
        native._publish_owned_wal_fixture(fd, _owned_generation())
    assert not (state / native._OWNED_WAL).exists()
    raw = (state / native._OWNED_WAL_TMP).read_bytes()
    old, new_sha = native._decode_owned_wal(raw)
    native._owned_wal_resource_drift(old, new_sha, _owned_bootstrap_resources(),
                                     unpublished=True)
    assert main.read_bytes() == native._OWNED_BOOTSTRAP_CONFIG
    assert not catalog.exists() and not vendor.exists() and not events
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_DOMAIN_REQUIRED"):
        native._publish_owned_wal_fixture(fd, _owned_generation())


@pytest.mark.parametrize("name", [native._OWNED_WAL, native._OWNED_WAL_TMP,
                                  native._OWNED_MANIFEST,
                                  native._OWNED_STAGES[V2_STATE],
                                  native._OWNED_STAGES[native._OWNED_MANIFEST]])
def test_owned_domain_refused_by_state_only_and_legacy_v1_interlocks(
    filesystem, name,
):
    from repocache import server_proposed_state_v2_store as v2
    from repocache import server_protected_state_store_v1 as v1
    _, state, _, _, _ = filesystem
    path = state / name
    path.write_bytes(b"owned-domain")
    path.chmod(0o600)
    sfd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert v2._multi_resource_pending(sfd, 0) is True
        with pytest.raises(ValueError, match="PROTECTED_V2_COHABITATION_REFUSED"):
            v1._refuse_proposed_v2_coexistence(sfd)
    finally:
        os.close(sfd)
    assert path.read_bytes() == b"owned-domain"

def _owned_fixture_paths(filesystem, old):
    fd, state, vendor, catalog, _ = filesystem
    (state / installer._CONFIG_MARKER).touch(mode=0o600)
    main = vendor.parent.parent / "repocache.d" / native._OWNED_MAIN
    paths = {
        V2_STATE: state / V2_STATE, native._OWNED_MAIN: main,
        native._INCLUDE: main.parent / native._INCLUDE, native._CATALOG: catalog,
        native._OWNED_MANIFEST: state / native._OWNED_MANIFEST,
    }
    for name, path in paths.items():
        if old[name] is not None:
            path.write_bytes(old[name])
            path.chmod(0o600 if name in native._OWNED_PRIVATE else 0o644)
    return paths


def _fixture_resource_bytes(paths):
    return {name: path.read_bytes() if path.exists() else None
            for name, path in paths.items()}


def _assert_owned_fixture_clean(filesystem, paths):
    _, state, vendor, _, events = filesystem
    assert not (state / native._OWNED_WAL).exists()
    assert not (state / native._OWNED_WAL_TMP).exists()
    assert not any((path.parent / native._OWNED_STAGES[name]).exists()
                   for name, path in paths.items())
    assert not vendor.exists() and not events


def test_owned_files_fixture_commit_first_and_repeat(filesystem):
    fd = filesystem[0]
    paths = _owned_fixture_paths(filesystem, _owned_bootstrap_resources())
    first = _owned_generation()
    second = _owned_generation(2, previous=json.loads(first[V2_STATE]), active=False)
    third = _owned_generation(3, previous=json.loads(second[V2_STATE]))
    assert first[native._CATALOG] != second[native._CATALOG]
    assert first[native._CATALOG] == third[native._CATALOG]
    for new in (first, second, third):
        result = native._apply_owned_files_fixture(fd, new)
        assert result["status"] == "OWNED_FIXTURE_FILES_COMMITTED"
        assert result["fixture_only"] and not result["authorizes_nginx_reload"]
        assert not result["authorizes_catalog_publication"]
        assert _fixture_resource_bytes(paths) == new
        _assert_owned_fixture_clean(filesystem, paths)
        assert native._recover_owned_files_fixture(fd)["status"] == "OWNED_FIXTURE_CLEAN"


class _OwnedFixturePowerLoss(BaseException):
    pass


@pytest.mark.parametrize("initial", [True, False])
@pytest.mark.parametrize("boundary", ["include", "main", "state", "catalog", "manifest"])
def test_owned_files_fixture_crash_after_each_resource_restores_exact_prior(
    filesystem, monkeypatch, initial, boundary,
):
    old = _owned_bootstrap_resources() if initial else _owned_generation()
    new = _owned_generation(1 if initial else 2,
                            previous=None if initial else json.loads(old[V2_STATE]),
                            active=initial)
    assert new[native._CATALOG] != old[native._CATALOG]
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    target = {"include": native._INCLUDE, "main": native._OWNED_MAIN,
              "state": V2_STATE, "catalog": native._CATALOG,
              "manifest": native._OWNED_MANIFEST}[boundary]
    actual = native._owned_write_resource

    def interrupted(*args):
        actual(*args)
        if args[3] == target:
            assert (state / native._OWNED_WAL).is_file()
            raise _OwnedFixturePowerLoss()

    monkeypatch.setattr(native, "_owned_write_resource", interrupted)
    with pytest.raises(_OwnedFixturePowerLoss):
        native._apply_owned_files_fixture(fd, new)
    assert (state / native._OWNED_WAL).is_file()
    monkeypatch.setattr(native, "_owned_write_resource", actual)
    assert native._recover_owned_files_fixture(fd)["status"] == "OWNED_FIXTURE_FILES_RESTORED"
    assert _fixture_resource_bytes(paths) == old
    _assert_owned_fixture_clean(filesystem, paths)


def test_owned_files_fixture_ordinary_failure_compensates_under_same_lock(
    filesystem, monkeypatch,
):
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    fd = filesystem[0]
    actual = native._owned_write_resource
    failed = False

    def fail_once(*args):
        nonlocal failed
        actual(*args)
        if args[3] == V2_STATE and not failed:
            failed = True
            raise OSError("injected write failure")

    monkeypatch.setattr(native, "_owned_write_resource", fail_once)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_APPLY_FILES_RESTORED"):
        native._apply_owned_files_fixture(fd, _owned_generation())
    assert _fixture_resource_bytes(paths) == old
    _assert_owned_fixture_clean(filesystem, paths)


def test_owned_files_fixture_recovery_refuses_foreign_target_before_cleanup(
    filesystem,
):
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    new = _owned_generation()
    wal = native._publish_owned_wal_fixture(fd, new)
    paths[native._OWNED_MAIN].write_bytes(b"foreign")
    stage = paths[native._INCLUDE].parent / native._OWNED_STAGES[native._INCLUDE]
    stage.write_bytes(b"partial")
    stage.chmod(0o600)
    before = _fixture_resource_bytes(paths)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_FOREIGN_DRIFT"):
        native._recover_owned_files_fixture(fd)
    assert _fixture_resource_bytes(paths) == before
    assert stage.read_bytes() == b"partial"
    assert (state / native._OWNED_WAL).read_bytes() == wal


@pytest.mark.parametrize("mode,content", [(0o600, b"partial"), (0o644, None)])
def test_owned_files_fixture_recovers_torn_or_complete_public_stage(
    filesystem, mode, content,
):
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    fd = filesystem[0]
    new = _owned_generation()
    native._publish_owned_wal_fixture(fd, new)
    stage = paths[native._INCLUDE].parent / native._OWNED_STAGES[native._INCLUDE]
    stage.write_bytes(new[native._INCLUDE] if content is None else content)
    stage.chmod(mode)
    assert native._recover_owned_files_fixture(fd)["status"] == "OWNED_FIXTURE_FILES_RESTORED"
    assert _fixture_resource_bytes(paths) == old
    _assert_owned_fixture_clean(filesystem, paths)


def test_owned_files_fixture_refuses_foreign_complete_stage_without_other_cleanup(filesystem):
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    wal = native._publish_owned_wal_fixture(fd, _owned_generation())
    first = state / native._OWNED_STAGES[V2_STATE]
    first.write_bytes(b"partial")
    first.chmod(0o600)
    foreign = paths[native._INCLUDE].parent / native._OWNED_STAGES[native._INCLUDE]
    foreign.write_bytes(b"foreign")
    foreign.chmod(0o644)
    with pytest.raises(native.NativeV2TransactionError, match="FOREIGN_STAGE"):
        native._recover_owned_files_fixture(fd)
    assert first.read_bytes() == b"partial" and foreign.read_bytes() == b"foreign"
    assert (state / native._OWNED_WAL).read_bytes() == wal


def test_owned_files_fixture_unpublished_wal_recovery_does_not_mutate_targets(filesystem):
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    raw = native._owned_wal_record(old, _owned_generation())
    pending = state / native._OWNED_WAL_TMP
    pending.write_bytes(raw)
    pending.chmod(0o600)
    result = native._recover_owned_files_fixture(fd)
    assert result["status"] == "OWNED_FIXTURE_UNPUBLISHED_WAL_DISCARDED"
    assert _fixture_resource_bytes(paths) == old
    _assert_owned_fixture_clean(filesystem, paths)


@pytest.mark.parametrize("operation", ["apply", "recover"])
def test_owned_files_fixture_refuses_live_root(operation):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="CURRENT_NAMESPACE_ROOT_WRITES_REFUSED"):
            if operation == "apply":
                native._apply_owned_files_fixture(fd, {})
            else:
                native._recover_owned_files_fixture(fd)
    finally:
        os.close(fd)

def test_owned_files_fixture_never_claims_rollback_after_wal_unlink_fault(
    filesystem, monkeypatch,
):
    old = _owned_bootstrap_resources()
    new = _owned_generation()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    actual = native._unlink_known

    def unlink_then_fail(directory, name, *args):
        actual(directory, name, *args)
        if name == native._OWNED_WAL:
            raise OSError("injected uncertainty after unlink")

    monkeypatch.setattr(native, "_unlink_known", unlink_then_fail)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_APPLY_RECOVERY_REQUIRED"):
        native._apply_owned_files_fixture(fd, new)
    assert _fixture_resource_bytes(paths) == new
    assert not (state / native._OWNED_WAL).exists()


def test_owned_files_fixture_rejects_changed_wal_before_next_write(filesystem, monkeypatch):
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    new = _owned_generation()
    actual = native._owned_write_resource

    def change_wal(*args):
        actual(*args)
        if args[3] == native._INCLUDE:
            (state / native._OWNED_WAL).write_bytes(b"foreign WAL")

    monkeypatch.setattr(native, "_owned_write_resource", change_wal)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_APPLY_RECOVERY_REQUIRED"):
        native._apply_owned_files_fixture(fd, new)
    expected = dict(old)
    expected[native._INCLUDE] = new[native._INCLUDE]
    assert _fixture_resource_bytes(paths) == expected
    assert (state / native._OWNED_WAL).read_bytes() == b"foreign WAL"


@pytest.mark.parametrize("initial", [True, False])
def test_owned_files_fixture_real_sigkill_then_interrupted_recovery_retries(
    filesystem, monkeypatch, initial,
):
    import signal

    old = _owned_bootstrap_resources() if initial else _owned_generation()
    new = _owned_generation(1 if initial else 2,
                            previous=None if initial else json.loads(old[V2_STATE]),
                            active=initial)
    assert new[native._CATALOG] != old[native._CATALOG]
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    actual = native._owned_write_resource
    pid = os.fork()
    if pid == 0:
        try:
            def kill_after_catalog(*args):
                actual(*args)
                if args[3] == native._CATALOG:
                    os.kill(os.getpid(), signal.SIGKILL)

            native._owned_write_resource = kill_after_catalog
            native._apply_owned_files_fixture(fd, new)
        finally:
            os._exit(77)
    _, status = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
    assert (state / native._OWNED_WAL).is_file()

    def fail_recovery_once(*args):
        actual(*args)
        if args[3] == native._OWNED_MAIN:
            raise _OwnedFixturePowerLoss()

    monkeypatch.setattr(native, "_owned_write_resource", fail_recovery_once)
    with pytest.raises(_OwnedFixturePowerLoss):
        native._recover_owned_files_fixture(fd)
    assert (state / native._OWNED_WAL).is_file()
    monkeypatch.setattr(native, "_owned_write_resource", actual)
    assert native._recover_owned_files_fixture(fd)["status"] == "OWNED_FIXTURE_FILES_RESTORED"
    assert _fixture_resource_bytes(paths) == old
    _assert_owned_fixture_clean(filesystem, paths)

@pytest.mark.parametrize("kind", ["symlink", "hardlink", "writable"])
def test_owned_files_fixture_refuses_unsafe_stage_inode(filesystem, tmp_path, kind):
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    wal = native._publish_owned_wal_fixture(fd, _owned_generation())
    stage = paths[native._INCLUDE].parent / native._OWNED_STAGES[native._INCLUDE]
    # Keep the link target outside the strictly allowlisted owned directory.
    # Otherwise the directory guard refuses the fixture before the stage-inode
    # guard is exercised. The foreign-entry guard has its own regression test.
    foreign = tmp_path / "unrelated-file"
    foreign.write_bytes(b"unrelated")
    foreign.chmod(0o644)
    if kind == "symlink":
        stage.symlink_to(foreign)
    elif kind == "hardlink":
        os.link(foreign, stage)
    else:
        stage.write_bytes(b"unsafe")
        stage.chmod(0o666)
    with pytest.raises(native.NativeV2TransactionError, match="FOREIGN_STAGE"):
        native._recover_owned_files_fixture(fd)
    assert os.path.lexists(stage)
    assert foreign.read_bytes() == b"unrelated"
    assert _fixture_resource_bytes(paths) == old
    assert (state / native._OWNED_WAL).read_bytes() == wal


def test_owned_files_fixture_refuses_malformed_unpublished_record(filesystem):
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    temporary = state / native._OWNED_WAL_TMP
    temporary.write_bytes(b"torn")
    temporary.chmod(0o600)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_INVALID"):
        native._recover_owned_files_fixture(fd)
    assert temporary.read_bytes() == b"torn"
    assert _fixture_resource_bytes(paths) == old


def test_owned_files_fixture_refuses_orphan_stage_without_wal(filesystem):
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    stage = paths[native._OWNED_MAIN].parent / native._OWNED_STAGES[native._OWNED_MAIN]
    stage.write_bytes(b"orphan")
    stage.chmod(0o600)
    with pytest.raises(native.NativeV2TransactionError, match="ORPHAN_STAGE"):
        native._recover_owned_files_fixture(filesystem[0])
    assert stage.read_bytes() == b"orphan"
    assert _fixture_resource_bytes(paths) == old


def test_owned_files_fixture_refuses_competing_domain_mid_transaction(
    filesystem, monkeypatch,
):
    old = _owned_bootstrap_resources()
    new = _owned_generation()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    actual = native._owned_write_resource
    foreign = state / native._STATE_STAGE

    def inject_foreign_stage(*args):
        actual(*args)
        if args[3] == native._INCLUDE:
            foreign.write_bytes(b"competing domain")
            foreign.chmod(0o600)

    monkeypatch.setattr(native, "_owned_write_resource", inject_foreign_stage)
    with pytest.raises(native.NativeV2TransactionError,
                       match="OWNED_WAL_APPLY_RECOVERY_REQUIRED"):
        native._apply_owned_files_fixture(fd, new)
    expected = dict(old)
    expected[native._INCLUDE] = new[native._INCLUDE]
    assert _fixture_resource_bytes(paths) == expected
    assert foreign.read_bytes() == b"competing domain"
    assert (state / native._OWNED_WAL).is_file()


def test_owned_wal_refuses_changed_temporary_record_before_publication(
    filesystem, monkeypatch,
):
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    actual = native._write_exclusive

    def change_temporary_record(directory, name, *args):
        actual(directory, name, *args)
        if name == native._OWNED_WAL_TMP:
            (state / name).write_bytes(b"changed record")

    monkeypatch.setattr(native, "_write_exclusive", change_temporary_record)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_CHANGED"):
        native._apply_owned_files_fixture(fd, _owned_generation())
    assert _fixture_resource_bytes(paths) == old
    assert not (state / native._OWNED_WAL).exists()
    assert (state / native._OWNED_WAL_TMP).read_bytes() == b"changed record"


@pytest.mark.parametrize("name", native._OWNED_PRIVATE)
def test_owned_files_fixture_recovers_empty_private_stage(filesystem, name):
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    fd = filesystem[0]
    native._publish_owned_wal_fixture(fd, _owned_generation())
    stage = paths[name].parent / native._OWNED_STAGES[name]
    stage.touch(mode=0o600)
    assert native._recover_owned_files_fixture(fd)["status"] == "OWNED_FIXTURE_FILES_RESTORED"
    assert _fixture_resource_bytes(paths) == old
    _assert_owned_fixture_clean(filesystem, paths)

@pytest.fixture
def owned_live_simulation(monkeypatch):
    """Actual fixture bytes/WAL, simulated private native observations only."""
    events = []
    monkeypatch.setattr(native, "_owned_live_observe", lambda fd: (123, (1, 2)))
    monkeypatch.setattr(native, "_owned_live_verify_listener", lambda *args: 999)
    def validate(root, state, resources):
        snapshot = native._validate_owned_resources(resources)
        generation = None if snapshot is None else snapshot["state_generation"]
        events.append(("validate", generation))
        return None if generation is None else {}, generation, "a" * 64
    def reload(root, identity):
        events.append(("reload",))
    def health(context, catalog, *, publish):
        events.append(("health", context[1], publish))
    monkeypatch.setattr(native, "_owned_live_validate", validate)
    monkeypatch.setattr(native, "_owned_live_reload", reload)
    monkeypatch.setattr(native, "_owned_live_health", health)
    return events


@pytest.mark.parametrize("initial", [True, False])
def test_owned_live_wal_catalog_withdrawal_and_commit(
    filesystem, monkeypatch, owned_live_simulation, initial,
):
    old = _owned_bootstrap_resources() if initial else _owned_generation()
    new = _owned_generation(1 if initial else 2,
                            previous=None if initial else json.loads(old[V2_STATE]),
                            active=initial)
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    events = owned_live_simulation
    def reload(root, identity):
        assert (state / native._OWNED_WAL).exists()
        assert not paths[native._CATALOG].exists()
        assert paths[native._INCLUDE].read_bytes() == new[native._INCLUDE]
        events.append(("reload",))
    def health(context, catalog, *, publish):
        if ("reload",) in events:
            assert (state / native._OWNED_WAL).exists()
            if publish:
                assert paths[native._CATALOG].read_bytes() == catalog
            else:
                assert not paths[native._CATALOG].exists()
        events.append(("health", context[1], publish))
    monkeypatch.setattr(native, "_owned_live_reload", reload)
    monkeypatch.setattr(native, "_owned_live_health", health)
    with native._owned_fixture_layout(fd, recovering=False) as layout:
        result = native._apply_owned_live_locked(fd, *layout, new)
    assert result["status"] == "OWNED_LIVE_COMMIT_OBSERVED"
    assert _fixture_resource_bytes(paths) == new
    _assert_owned_fixture_clean(filesystem, paths)
    assert events.count(("reload",)) == 1


@pytest.mark.parametrize("initial", [True, False])
def test_owned_live_wal_rollback_retains_record_until_prior_health(
    filesystem, monkeypatch, owned_live_simulation, initial,
):
    old = _owned_bootstrap_resources() if initial else _owned_generation()
    new = _owned_generation(1 if initial else 2,
                            previous=None if initial else json.loads(old[V2_STATE]),
                            active=initial)
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    calls = []
    def reload(root, identity):
        assert (state / native._OWNED_WAL).exists()
        assert not paths[native._CATALOG].exists()
        calls.append(paths[native._OWNED_MAIN].read_bytes())
        if len(calls) == 1:
            raise native.NativeV2TransactionError("injected reload fault")
    monkeypatch.setattr(native, "_owned_live_reload", reload)
    with native._owned_fixture_layout(fd, recovering=False) as layout:
        with pytest.raises(native.NativeV2TransactionError, match="OWNED_LIVE_APPLY_ROLLED_BACK"):
            native._apply_owned_live_locked(fd, *layout, new)
    assert calls == [new[native._OWNED_MAIN], old[native._OWNED_MAIN]]
    assert _fixture_resource_bytes(paths) == old
    _assert_owned_fixture_clean(filesystem, paths)


def test_owned_live_failed_compensation_retains_wal_and_withdraws_catalog(
    filesystem, monkeypatch, owned_live_simulation,
):
    old = _owned_generation()
    new = _owned_generation(2, previous=json.loads(old[V2_STATE]), active=False)
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    def fail(*args):
        raise native.NativeV2TransactionError("injected unavailable service")
    monkeypatch.setattr(native, "_owned_live_reload", fail)
    with native._owned_fixture_layout(fd, recovering=False) as layout:
        with pytest.raises(native.NativeV2TransactionError, match="OWNED_LIVE_APPLY_RECOVERY_REQUIRED"):
            native._apply_owned_live_locked(fd, *layout, new)
    assert not paths[native._CATALOG].exists()
    assert (state / native._OWNED_WAL).exists()
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_LIVE_WAL_REQUIRES_RUNTIME_RECOVERY"):
        native._recover_owned_files_fixture(fd)
    monkeypatch.setattr(native, "_owned_live_reload", lambda *args: None)
    with native._owned_fixture_layout(fd, recovering=True) as layout:
        assert native._recover_owned_live_locked(fd, *layout)["status"] == "OWNED_LIVE_ROLLBACK_OBSERVED"
    assert _fixture_resource_bytes(paths) == old
    _assert_owned_fixture_clean(filesystem, paths)


def test_owned_live_wal_never_accepts_v2_catalog_gap():
    old = _owned_generation()
    new = _owned_generation(2, previous=json.loads(old[V2_STATE]), active=False)
    current = dict(old)
    current[native._CATALOG] = None
    _, hashes = native._decode_owned_wal(native._owned_wal_record(old, new))
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_FOREIGN_DRIFT"):
        native._owned_wal_resource_drift(old, hashes, current, unpublished=False)
    live = native._owned_wal_record(old, new, live=True)
    _, hashes = native._decode_owned_wal(live)
    native._owned_wal_resource_drift(old, hashes, current, unpublished=False,
                                      catalog_withdrawal=True)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_UNPUBLISHED_DRIFT"):
        native._owned_wal_resource_drift(old, hashes, current, unpublished=True,
                                          catalog_withdrawal=True)

def test_owned_live_unpublished_wal_requires_prior_runtime_proof(
    filesystem, monkeypatch, owned_live_simulation,
):
    old = _owned_generation()
    new = _owned_generation(2, previous=json.loads(old[V2_STATE]), active=False)
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    temporary = state / native._OWNED_WAL_TMP
    temporary.write_bytes(native._owned_wal_record(old, new, live=True))
    temporary.chmod(0o600)
    def fail(*args, **kwargs):
        raise native.NativeV2TransactionError("injected prior health fault")
    prior_health = native._owned_live_health
    monkeypatch.setattr(native, "_owned_live_health", fail)
    with native._owned_fixture_layout(fd, recovering=True) as layout:
        with pytest.raises(native.NativeV2TransactionError, match="prior health fault"):
            native._recover_owned_live_locked(fd, *layout)
    assert temporary.exists()
    assert _fixture_resource_bytes(paths) == old
    monkeypatch.setattr(native, "_owned_live_health", prior_health)
    with native._owned_fixture_layout(fd, recovering=True) as layout:
        result = native._recover_owned_live_locked(fd, *layout)
    assert result["status"] == "OWNED_LIVE_UNPUBLISHED_WAL_DISCARDED"
    _assert_owned_fixture_clean(filesystem, paths)


def test_owned_live_catalog_rewithdrawn_after_failed_prior_exposure(
    filesystem, monkeypatch, owned_live_simulation,
):
    old = _owned_generation()
    new = _owned_generation(2, previous=json.loads(old[V2_STATE]), active=False)
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    with native._owned_fixture_layout(fd, recovering=False) as layout:
        native._publish_owned_wal_locked(*layout[:3], old, new, layout[3], live=True)
    def health(context, catalog, *, publish):
        if publish:
            raise native.NativeV2TransactionError("injected prior catalog exposure fault")
    monkeypatch.setattr(native, "_owned_live_health", health)
    with native._owned_fixture_layout(fd, recovering=True) as layout:
        with pytest.raises(native.NativeV2TransactionError, match="prior catalog exposure fault"):
            native._recover_owned_live_locked(fd, *layout)
    assert not paths[native._CATALOG].exists()
    assert (state / native._OWNED_WAL).exists()
    monkeypatch.setattr(native, "_owned_live_health", lambda *a, **kw: None)
    with native._owned_fixture_layout(fd, recovering=True) as layout:
        native._recover_owned_live_locked(fd, *layout)
    assert _fixture_resource_bytes(paths) == old
    _assert_owned_fixture_clean(filesystem, paths)


def test_owned_live_reload_fixed_arguments_and_changed_unit_refusal(monkeypatch):
    from types import SimpleNamespace
    identity = (123, (1, 2))
    observations = iter([identity, (124, (1, 2))])
    monkeypatch.setattr(native, "_owned_live_observe", lambda fd: next(observations))
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(native.subprocess, "run", run)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_LIVE_UNIT_CHANGED"):
        native._owned_live_reload(0, identity)
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv == ("/usr/bin/systemctl", "reload", "repocache-nginx.service")
    assert kwargs["shell"] is False and kwargs["timeout"] == 10
    assert kwargs["cwd"] == "/" and kwargs["env"] == native._ENV


def test_owned_live_generation_wait_is_bounded_and_rechecks_unit(monkeypatch):
    identity = (123, (1, 2))
    observations = iter([identity, identity, (124, (1, 2))])
    monkeypatch.setattr(native, "_owned_live_observe", lambda fd: next(observations))
    monkeypatch.setattr(native.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(native, "_owned_live_verify_listener", lambda *args: 999)
    calls = []
    def stale(*args, **kwargs):
        calls.append(1)
        raise native.NativeV2TransactionError("stale generation")
    monkeypatch.setattr(native, "_owned_live_health", stale)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_LIVE_UNIT_CHANGED"):
        native._owned_live_wait_generation(0, identity, ({}, 2, "a" * 64))
    assert len(calls) == 2

@pytest.mark.parametrize("reload", [True, False])
def test_owned_live_committed_reload_never_writes(
    filesystem, monkeypatch, owned_live_simulation, reload,
):
    old = _owned_generation()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    before = {name: path.stat() for name, path in paths.items()}
    with native._owned_fixture_layout(fd, recovering=False) as layout:
        result = native._reload_owned_live_committed_locked(fd, *layout, reload=reload)
    assert result["status"] == ("OWNED_LIVE_RELOADED" if reload else "OWNED_LIVE_NO_CHANGE")
    assert owned_live_simulation.count(("reload",)) == int(reload)
    assert _fixture_resource_bytes(paths) == old
    for name, path in paths.items():
        after = path.stat()
        assert (after.st_ino, after.st_mtime_ns) == (
            before[name].st_ino, before[name].st_mtime_ns)
    _assert_owned_fixture_clean(filesystem, paths)


def test_owned_live_committed_reload_refuses_pending_before_service_observation(
    filesystem, owned_live_simulation,
):
    old = _owned_generation()
    new = _owned_generation(2, previous=json.loads(old[V2_STATE]), active=False)
    _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    with native._owned_fixture_layout(fd, recovering=False) as layout:
        native._publish_owned_wal_locked(*layout[:3], old, new, layout[3], live=True)
    with native._owned_fixture_layout(fd, recovering=True) as layout:
        with pytest.raises(native.NativeV2TransactionError, match="ORPHAN_STAGE"):
            native._reload_owned_live_committed_locked(fd, *layout)
    assert owned_live_simulation == []
    assert (state / native._OWNED_WAL).exists()


@pytest.mark.parametrize("stale", [False, True])
def test_owned_live_prepare_fixed_intake_cas(
    filesystem, monkeypatch, stale,
):
    old = _owned_bootstrap_resources()
    new = _owned_generation()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    report = {"expected_generation": 1 if stale else 0,
              "expected_state_sha256": None}
    monkeypatch.setattr(native, "_load_private_under_root",
                        lambda *args, **kwargs: (report, new[V2_STATE]))
    monkeypatch.setattr(native, "_verify_tls_pair", lambda *args, **kwargs: "a" * 64)
    monkeypatch.setattr(native, "_resolve_pins",
                        lambda doc: {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}})
    with native._owned_fixture_layout(fd, recovering=False) as layout:
        if stale:
            with pytest.raises(native.NativeV2TransactionError, match="STATE_STALE"):
                native._prepare_owned_live_candidate_locked(fd, *layout[:3], "debian")
        else:
            assert native._prepare_owned_live_candidate_locked(
                fd, *layout[:3], "debian") == (old, new, report)
    assert _fixture_resource_bytes(paths) == old
    _assert_owned_fixture_clean(filesystem, paths)


def _listener_table(*rows):
    return ("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
            + "\n".join(rows) + "\n").encode("ascii")


@pytest.mark.parametrize("address,ipv6,expected", [
    ("0100007F", False, "127.0.0.1"),
    ("00000000", False, "0.0.0.0"),
    ("00000000000000000000000001000000", True, "::1"),
    ("00000000000000000000000000000000", True, "::"),
])
def test_owned_listener_parses_kernel_address_and_only_listen(address, ipv6, expected):
    table = _listener_table(
        f"0: {address}:1F48 {address}:0000 0A 0:0 0:0 0 0 0 123",
        f"1: {address}:1F48 {address}:0000 01 0:0 0:0 0 0 0 456",
        f"2: {address}:1F49 {address}:0000 0A 0:0 0:0 0 0 0 789",
    )
    assert native._owned_listener_rows(table, ipv6=ipv6, port=8008) == [(expected, 123)]


@pytest.mark.parametrize("rows,sockets", [
    ([], {123}),
    ([("127.0.0.1", 123)], {456}),
    ([("0.0.0.0", 123)], {123}),
    ([("127.0.0.1", 123), ("::", 456)], {123, 456}),
    ([("127.0.0.1", 123), ("127.0.0.1", 456)], {123, 456}),
])
def test_owned_listener_refuses_foreign_or_ambiguous_binding(rows, sockets):
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_LIVE_LISTENER_UNVERIFIED"):
        native._owned_require_listener(rows, sockets, "127.0.0.1")


def test_owned_listener_matches_unique_master_inode():
    assert native._owned_require_listener([("127.0.0.1", 123)], {123, 456},
                                          "127.0.0.1") == 123


def test_owned_live_health_refuses_listener_replacement(monkeypatch):
    inodes = iter([123, 456])
    monkeypatch.setattr(native, "_owned_live_verify_listener", lambda *args: next(inodes))
    monkeypatch.setattr(native, "_owned_live_health", lambda *args, **kwargs: None)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_LIVE_LISTENER_CHANGED"):
        native._owned_live_health_bound(0, (123, (1, 2)), (None, None, None), None,
                                        publish=False)


def test_owned_live_intake_rechecked_at_wal_boundary(
    filesystem, monkeypatch, owned_live_simulation,
):
    old = _owned_bootstrap_resources()
    new = _owned_generation()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    report = {"expected_generation": 0, "expected_state_sha256": None}
    monkeypatch.setattr(native, "_load_private_under_root",
                        lambda *a, **kw: (report, b"changed intake"))
    with native._owned_fixture_layout(fd, recovering=False) as layout:
        with pytest.raises(native.NativeV2TransactionError, match="CANDIDATE_CHANGED"):
            native._apply_owned_live_locked(fd, *layout, new, expected_intake=report)
    assert _fixture_resource_bytes(paths) == old
    _assert_owned_fixture_clean(filesystem, paths)


def test_owned_live_fixed_intake_apply_and_replay(
    filesystem, monkeypatch, owned_live_simulation,
):
    old = _owned_bootstrap_resources()
    new = _owned_generation()
    paths = _owned_fixture_paths(filesystem, old)
    fd, state, _, _, _ = filesystem
    report = {"expected_generation": 0, "expected_state_sha256": None}
    monkeypatch.setattr(native, "_load_private_under_root",
                        lambda *a, **kw: (report, new[V2_STATE]))
    monkeypatch.setattr(native, "_verify_tls_pair", lambda *a, **kw: "a" * 64)
    monkeypatch.setattr(native, "_resolve_pins",
                        lambda doc: {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}})
    with native._owned_fixture_layout(fd, recovering=False) as layout:
        assert native._apply_prepared_owned_live_locked(fd, *layout, "debian")[
            "status"] == "OWNED_LIVE_COMMIT_OBSERVED"
    with native._owned_fixture_layout(fd, recovering=False) as layout:
        assert native._apply_prepared_owned_live_locked(fd, *layout, "debian")[
            "status"] == "OWNED_LIVE_NO_CHANGE"
    assert _fixture_resource_bytes(paths) == new
    _assert_owned_fixture_clean(filesystem, paths)


@pytest.mark.parametrize("operation", ["APPLY_V2", "RECOVER_V2", "RELOAD_V2"])
def test_owned_socket_claim_never_dispatches_vendor(filesystem, monkeypatch, operation):
    fd, state, _, _, _ = filesystem
    (state / (native.OWNED_NGINX_CONFIG_MARKER_PREFIX + "foreign")).touch(mode=0o600)
    monkeypatch.setattr(native, "inspect_effective_native_nginx_unit",
                        lambda *_: pytest.fail("vendor fallthrough"))
    monkeypatch.setattr(native, "_apply_locked",
                        lambda *_a, **_kw: pytest.fail("vendor apply"))
    monkeypatch.setattr(native, "_recover_locked",
                        lambda *_: pytest.fail("vendor recovery"))
    monkeypatch.setattr(native, "_reload_owned_locked",
                        lambda *_: pytest.fail("vendor reload"))
    def reject(*args):
        assert args[0] == fd and args[-1] == operation
        raise native.NativeV2TransactionError("OWNED_SOCKET_TEST_REFUSAL")
    monkeypatch.setattr(native, "_owned_socket_operation_locked", reject)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_SOCKET_TEST_REFUSAL"):
        native._operation_under_root(fd, distribution="debian",
                                     operation=operation, socket_dispatch=True)


def test_owned_socket_active_candidate_refused_before_wal(filesystem, monkeypatch):
    from contextlib import contextmanager
    fd, state, _, _, _ = filesystem
    @contextmanager
    def layout(*_a, **_kw):
        yield (1, 2, 3, lambda: None)
    monkeypatch.setattr(native, "_owned_layout_locked", layout)
    monkeypatch.setattr(native, "_owned_socket_host_boundary", lambda *_: None)
    monkeypatch.setattr(native, "_owned_socket_recheck_write_boundary", lambda *_: None)
    monkeypatch.setattr(native, "_read_owned_resources",
                        lambda *_: {native.V2_STATE: None})
    monkeypatch.setattr(native, "_validate_owned_resources", lambda *_a, **_kw: None)
    candidate = _owned_generation(active=True)[V2_STATE]
    monkeypatch.setattr(native, "_load_private_under_root",
                        lambda *_a, **_kw: ({"expected_generation": 0}, candidate))
    monkeypatch.setattr(native, "_prepare_owned_live_candidate_locked",
                        lambda *_: pytest.fail("active candidate reached preparation"))
    with pytest.raises(native.NativeV2TransactionError,
                       match="OWNED_SOCKET_ACTIVE_STORAGE_UNVERIFIED"):
        native._owned_socket_operation_locked(fd, 1, "debian", "APPLY_V2")
    assert not (state / native._OWNED_WAL).exists()


@pytest.mark.parametrize("name", ["repocache.conf", "repocache-managed.conf"])
def test_isolated_owned_layout_never_adopts_legacy_siblings(filesystem, name):
    fd, state, vendor, _, _ = filesystem
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    foreign = vendor.parent.parent / name
    foreign.symlink_to("missing")
    with pytest.raises(native.NativeV2TransactionError, match="ORPHAN_STAGE"):
        with native._owned_fixture_layout(fd, recovering=False):
            pytest.fail("legacy sibling was adopted")
    assert foreign.is_symlink()
    assert _fixture_resource_bytes(paths) == old
    assert not (state / native._OWNED_WAL).exists()


def test_old_path_claim_is_not_new_directory_authority(filesystem):
    fd, state, vendor, _, _ = filesystem
    main = vendor.parent.parent / "repocache.d" / native._OWNED_MAIN
    main.write_bytes(native._OWNED_BOOTSTRAP_CONFIG)
    main.chmod(0o644)
    old_claim = state / (installer._CONFIG_MARKER_PREFIX
                         + hashlib.sha256(native._OWNED_BOOTSTRAP_CONFIG).hexdigest())
    old_claim.touch(mode=0o600)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_CONTEXT_CLAIM_REQUIRED"):
        with native._owned_fixture_layout(fd, recovering=False):
            pytest.fail("old path claim reused")
    assert old_claim.exists()
    assert main.read_bytes() == native._OWNED_BOOTSTRAP_CONFIG


def test_isolated_owned_layout_refuses_unrelated_directory_entry(filesystem):
    fd, state, vendor, _, _ = filesystem
    old = _owned_bootstrap_resources()
    paths = _owned_fixture_paths(filesystem, old)
    foreign = paths[native._OWNED_MAIN].parent / "foreign.conf"
    foreign.write_bytes(b"foreign")
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_DIRECTORY_FOREIGN_ENTRY"):
        with native._owned_fixture_layout(fd, recovering=False):
            pytest.fail("unrelated file in isolated directory adopted")
    assert foreign.read_bytes() == b"foreign"
    assert _fixture_resource_bytes(paths) == old


def test_socket_apply_binds_storage_check_to_exact_prepared_candidate(
    filesystem, monkeypatch, owned_live_simulation,
):
    fd, state, _, _, _ = filesystem
    old = _owned_bootstrap_resources()
    new = _owned_generation(active=False)
    paths = _owned_fixture_paths(filesystem, old)
    report = {"expected_generation": 0, "expected_state_sha256": None}
    monkeypatch.setattr(native, "_owned_socket_host_boundary", lambda *_: None)
    monkeypatch.setattr(native, "_owned_socket_recheck_write_boundary", lambda *_: None)
    monkeypatch.setattr(native, "_load_private_under_root",
                        lambda *_a, **_kw: (report, new[V2_STATE]))
    monkeypatch.setattr(native, "_prepare_owned_live_candidate_locked",
                        lambda *_: (old, new, report))
    with native._locked(fd, 0) as state_fd:
        result = native._owned_socket_operation_locked(fd, state_fd, "debian", "APPLY_V2")
    assert result == {"status": "NATIVE_V2_COMMITTED", "state_generation": 1}
    assert _fixture_resource_bytes(paths) == new
    _assert_owned_fixture_clean(filesystem, paths)


def test_socket_recovery_dispatches_prior_snapshot_not_partial_current(
    filesystem, monkeypatch, owned_live_simulation,
):
    fd, state, _, _, _ = filesystem
    old = _owned_bootstrap_resources()
    new = _owned_generation(active=False)
    paths = _owned_fixture_paths(filesystem, old)
    monkeypatch.setattr(native, "_owned_socket_host_boundary", lambda *_: None)
    monkeypatch.setattr(native, "_owned_socket_recheck_write_boundary", lambda *_: None)
    with native._owned_fixture_layout(fd, recovering=False) as layout:
        state_fd, nginx_fd, public_fd, check_layout = layout
        native._publish_owned_wal_locked(state_fd, nginx_fd, public_fd,
                                        old, new, check_layout, live=True)
    paths[native._INCLUDE].write_bytes(new[native._INCLUDE])
    paths[native._INCLUDE].chmod(0o644)
    with native._locked(fd, 0) as state_fd:
        result = native._owned_socket_operation_locked(fd, state_fd, "debian", "RECOVER_V2")
    assert result == {"status": "NATIVE_V2_ROLLED_BACK"}
    assert _fixture_resource_bytes(paths) == old
    _assert_owned_fixture_clean(filesystem, paths)

@pytest.mark.parametrize("key", ["cache_root", "log_root"])
def test_owned_active_candidate_refuses_unbound_storage_paths(key):
    cfg = document(1)
    cfg["expected_state_generation"] = 1
    cfg["deployment"]["paths"]["generated_include"] = native._OWNED_INCLUDE_PATH
    cfg["deployment"]["paths"][key] = "/tmp/foreign"
    cfg["repositories"][0]["desired_state"] = "active"
    with pytest.raises(native.NativeV2TransactionError,
                       match="OWNED_CONTEXT_LAYOUT_UNSUPPORTED"):
        native._render_owned_managed_candidate(
            cfg, 1, "debian", {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}},
        )

@pytest.mark.parametrize(("distribution", "directive", "other"), [
    ("debian", b"user www-data www-data;", "almalinux"),
    ("almalinux", b"user nginx nginx;", "debian"),
])
def test_managed_main_requires_exact_fixed_distro_worker(distribution, directive, other):
    cfg = document(1)
    cfg["expected_state_generation"] = 1
    cfg["deployment"]["paths"]["generated_include"] = native._OWNED_INCLUDE_PATH
    cfg["repositories"][0]["desired_state"] = "disabled"
    main, include, catalog = native._render_owned_managed_candidate(cfg, 1, distribution, {})
    assert main.splitlines()[1] == directive
    assert main == native._owned_managed_config(distribution)
    native._verify_owned_context_dump(_owned_dump(include, distribution=distribution),
                                      include, managed_main=main)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_CONTEXT_DUMP_MISMATCH"):
        native._verify_owned_context_dump(_owned_dump(include, distribution=other),
                                          include, managed_main=main)
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_CONTEXT_DUMP_INVALID"):
        native._verify_owned_context_dump(_owned_dump(include, distribution=distribution),
                                          include, managed_main=main.replace(directive, b"user root;"))


def test_owned_managed_worker_identity_not_caller_selectable():
    for value in ("root", "nginx", "www-data", "", None):
        with pytest.raises(native.NativeV2TransactionError, match="DISTRIBUTION_UNSUPPORTED"):
            native._owned_managed_config(value)

def test_bootstrap_wal_binds_selected_distro_and_managed_wal_refuses_switch():
    old = _owned_bootstrap_resources()
    debian = _owned_generation(active=False)
    alma = dict(debian)
    alma[native._OWNED_MAIN] = native._owned_managed_config("almalinux")
    alma[native._OWNED_MANIFEST] = native._owned_manifest_for(
        alma[V2_STATE], alma[native._OWNED_MAIN],
        alma[native._INCLUDE], alma[native._CATALOG],
    )
    assert native._validate_owned_resources(alma, distribution="almalinux")
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_MANIFEST_DRIFT"):
        native._validate_owned_resources(alma, distribution="debian")
    raw = native._owned_wal_record(old, alma, live=True)
    assert native._decode_owned_wal(raw, distribution="almalinux")[0] == old
    with pytest.raises(native.NativeV2TransactionError, match="OWNED_WAL_INVALID"):
        native._decode_owned_wal(raw, distribution="debian")
    next_generation = _owned_generation(2, previous=json.loads(alma[V2_STATE]), active=False)
    with pytest.raises(native.NativeV2TransactionError,
                       match="OWNED_WAL_MANAGED_IDENTITY_CHANGED"):
        native._owned_wal_record(alma, next_generation, live=True)


@pytest.mark.parametrize("distribution", ["debian", "almalinux"])
def test_managed_context_explicit_private_temp_paths(distribution):
    main = native._owned_managed_config(distribution)
    for directive, name in native._OWNED_RUNTIME_TEMP_NAMES:
        assert main.count(f"{directive} /run/repocache-nginx/{name};".encode("ascii")) == 1
        assert directive.encode("ascii") not in native._OWNED_BOOTSTRAP_CONFIG
    assert b"/var/lib/nginx" not in main


@pytest.mark.parametrize("fault", ["none", "missing", "symlink", "mode", "group",
                                  "owner", "nonempty", "extra", "xattr"])
def test_debian_runtime_scratch_is_fixed_and_safe(tmp_path, monkeypatch, fault):
    import stat
    from types import SimpleNamespace
    # Use actual root-owned disposable paths; independent of distro passwd DB.
    monkeypatch.setattr(native.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=33))
    runtime = tmp_path / "run/repocache-nginx"
    runtime.mkdir(parents=True, mode=0o755)
    runtime.chmod(0o755)
    for _, name in native._OWNED_RUNTIME_TEMP_NAMES:
        path = runtime / name
        path.mkdir(mode=0o700)
        os.chown(path, 33, 0)
    first = runtime / native._OWNED_RUNTIME_TEMP_NAMES[0][1]
    if fault == "missing":
        first.rmdir()
    elif fault == "symlink":
        first.rmdir()
        first.symlink_to(tmp_path, target_is_directory=True)
    elif fault == "mode":
        first.chmod(0o770)
    elif fault == "group":
        os.chown(first, 33, 33)
    elif fault == "owner":
        os.chown(first, 65534, 0)
    elif fault == "nonempty":
        (first / "foreign").write_bytes(b"retain")
    elif fault == "extra":
        (runtime / "foreign").mkdir()
    elif fault == "xattr":
        os.setxattr(first, "user.repocache-ci", b"retain")
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if fault in ("none", "missing"):
            _, found = native._owned_debian_runtime_temps(
                fd, require_all=fault == "none", inactive=True,
            )
            assert len(found) == (5 if fault == "none" else 4)
            if fault == "missing":
                with pytest.raises(native.NativeV2TransactionError,
                                   match="OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED"):
                    native._owned_debian_runtime_temps(fd, require_all=True)
        else:
            with pytest.raises(native.NativeV2TransactionError,
                               match="OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED"):
                native._owned_debian_runtime_temps(fd, require_all=True, inactive=True)
        if fault == "none":
            # Recoverable partial mkdir: root-owned and empty before nginx
            # chown, but never acceptable as a completed native observation.
            os.chown(first, 0, 0)
            native._owned_debian_runtime_temps(fd, require_all=False, inactive=True)
            with pytest.raises(native.NativeV2TransactionError,
                               match="OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED"):
                native._owned_debian_runtime_temps(fd, require_all=True)
            assert stat.S_IMODE(first.stat().st_mode) == 0o700
    finally:
        os.close(fd)


def test_owned_wal_refuses_rehashed_unapproved_egress_tuple():
    new = _owned_generation()
    raw = new[native._INCLUDE]
    assert raw.count(b"server 8.8.8.8:443;") == 1
    new[native._INCLUDE] = raw.replace(b"server 8.8.8.8:443;", b"server 8.8.8.8:8008;")
    new[native._OWNED_MANIFEST] = native._owned_manifest_for(
        new[V2_STATE], new[native._OWNED_MAIN], new[native._INCLUDE], new[native._CATALOG],
    )
    with pytest.raises(native.NativeV2TransactionError,
                       match="OWNED_WAL_EGRESS_CANDIDATE_INVALID"):
        native._owned_wal_record(_owned_bootstrap_resources(), new)


@pytest.mark.parametrize("initial", [True, False])
def test_live_egress_recovery_derives_exact_policies_without_catalog(initial, monkeypatch):
    old = _owned_bootstrap_resources() if initial else _owned_generation()
    previous = None if initial else json.loads(old[V2_STATE])
    new = _owned_generation(1 if initial else 2, previous=previous, active=initial)
    wal = native._owned_wal_record(old, new, live=True)
    def never(*args, **kwargs):
        pytest.fail("recovery must not resolve DNS")
    monkeypatch.setattr(native, "bounded_getaddrinfo", never)
    partial = native._owned_live_egress_recovery_candidates(
        wal, old, distribution="debian", worker_uid=33)
    assert partial["proposed"] is None
    current = {**new, native._CATALOG: None, native._OWNED_MANIFEST: old[native._OWNED_MANIFEST]}
    report = native._owned_live_egress_recovery_candidates(
        wal, current, distribution="debian", worker_uid=33)
    assert report["prior"]["generation"] == (0 if initial else 1)
    assert report["proposed"]["generation"] == (1 if initial else 2)
    assert report["prior"]["destinations"] == (() if initial else (("8.8.8.8", 443),))
    assert report["proposed"]["destinations"] == ((("8.8.8.8", 443),) if initial else ())
    assert report["wal_sha256"] == hashlib.sha256(wal).hexdigest()
    assert all(report[key] is False for key in (
        "runtime_egress_verified", "authorizes_firewall_change",
        "authorizes_nginx_activation", "authorizes_catalog_publication"))
    assert "policy drop;" in report["prior"]["nft_candidate"]
    if initial:
        assert '127.0.0.1 tcp dport 8008' in report["prior"]["nft_candidate"]


def test_live_egress_recovery_refuses_foreign_and_inconsistent_wal():
    old = _owned_bootstrap_resources()
    new = _owned_generation()
    current = {**new, native._CATALOG: None}
    raw = native._owned_wal_record(old, new, live=True)
    with pytest.raises(native.NativeV2TransactionError):
        native._owned_live_egress_recovery_candidates(
            native._owned_wal_record(old, new), current, distribution="debian", worker_uid=33)
    with pytest.raises(native.NativeV2TransactionError, match="FOREIGN_DRIFT"):
        native._owned_live_egress_recovery_candidates(
            raw, {**current, native._INCLUDE: b"foreign"}, distribution="debian", worker_uid=33)
    altered = json.loads(raw)
    altered["new_sha256"][native._CATALOG] = "0" * 64
    with pytest.raises(native.NativeV2TransactionError, match="PROPOSED_WAL_DRIFT"):
        native._owned_live_egress_recovery_candidates(
            _canon(altered), current, distribution="debian", worker_uid=33)



@pytest.mark.parametrize("fault", ["none", "restore", "catalog", "partial",
                                    "wal-drift", "resource-drift", "owner-drift"])
def test_owned_egress_replacement_requires_exact_durable_wal_and_withdrawn_catalog(
        monkeypatch, fault):
    old = _owned_bootstrap_resources()
    new = _owned_generation()
    wal = native._owned_wal_record(old, new, live=True)
    current = [{**new, native._CATALOG: None}]
    if fault == "catalog":
        current[0] = new
    elif fault == "partial":
        current[0] = {**old, native._CATALOG: None}
    checks = []
    calls = []

    def exact(fd, raw):
        assert fd == 101 and raw == wal
        checks.append("wal")
        if fault == "wal-drift" and calls:
            raise native.NativeV2TransactionError("WAL_CHANGED")

    def read(*fds):
        assert fds == (101, 102, 103)
        return dict(current[0])

    def owner():
        checks.append("owner")
        if fault == "owner-drift" and calls:
            raise native.NativeV2TransactionError("OWNER_CHANGED")

    def replace(previous, proposed, *, namespace_identity, recheck_owned):
        assert namespace_identity == (7, 9)
        calls.append((previous, proposed))
        if fault == "resource-drift":
            current[0][native._CATALOG] = b"unexpected"
        recheck_owned()
        return {"status": "NAMESPACE_EGRESS_REPLACEMENT_OBSERVED"}

    monkeypatch.setattr(native, "_owned_require_exact_wal", exact)
    monkeypatch.setattr(native, "_read_owned_resources", read)
    monkeypatch.setattr(native, "_replace_fixed_namespace_egress", replace)
    kwargs = dict(wal=wal, distribution="debian", worker_uid=33,
                  namespace_identity=(7, 9), recheck_namespace_owner=owner,
                  restore=fault == "restore")
    if fault in ("none", "restore"):
        result = native._owned_live_replace_egress_locked(
            101, 102, 103, lambda: checks.append("layout"), **kwargs)
        assert result["wal_sha256"] == hashlib.sha256(wal).hexdigest()
        assert (result["from_generation"], result["to_generation"]) == (
            (1, 0) if fault == "restore" else (0, 1))
        assert "8.8.8.8" in calls[0][0 if fault == "restore" else 1]
        assert "8.8.8.8" not in calls[0][1 if fault == "restore" else 0]
        assert not result["authorizes_catalog_publication"]
        assert not result["authorizes_nginx_activation"]
    else:
        with pytest.raises(native.NativeV2TransactionError):
            native._owned_live_replace_egress_locked(
                101, 102, 103, lambda: checks.append("layout"), **kwargs)
        assert len(calls) == (0 if fault in ("catalog", "partial") else 1)


@pytest.mark.parametrize("kind", ["bootstrap", "disabled", "active"])
@pytest.mark.parametrize("fault", ["none", "pending", "orphan", "resource-drift", "owner-drift"])
def test_committed_boot_egress_retains_generation_and_excludes_pending(
        filesystem, monkeypatch, kind, fault):
    rootfd, state, _, _, _ = filesystem
    old = (_owned_bootstrap_resources() if kind == "bootstrap" else
           _owned_generation(active=kind == "active"))
    paths = _owned_fixture_paths(filesystem, old)
    if fault == "pending":
        # Presence, including an invalid pending intent, is sufficient to
        # forbid boot-time policy initialization before recovery.
        (state / native._OWNED_WAL).write_bytes(b"pending")
        (state / native._OWNED_WAL).chmod(0o600)
    elif fault == "orphan":
        orphan = paths[native._OWNED_MAIN].parent / native._OWNED_STAGES[native._OWNED_MAIN]
        orphan.write_bytes(b"orphan")
        orphan.chmod(0o644)
    calls = []
    def owned():
        if fault == "owner-drift" and calls:
            raise native.NativeV2TransactionError("OWNER_CHANGED")
    def prepare(got_root, got_state, rules, **kw):
        assert got_root == rootfd
        assert got_state == statefd
        assert kw["namespace_identity"] == (17, 29)
        assert kw["generation"] == (0 if kind == "bootstrap" else 1)
        assert ("8.8.8.8" in rules) == (kind == "active")
        assert kw["profile_receipt_sha256"] == "a" * 64
        assert kw["executable_receipt_sha256"] == "b" * 64
        if kind != "bootstrap":
            assert kw["generation_manifest_sha256"] == hashlib.sha256(
                old[native._OWNED_MANIFEST]).hexdigest()
        calls.append(kw["generation_manifest_sha256"])
        if fault == "resource-drift":
            paths[native._OWNED_MAIN].write_bytes(b"foreign")
        kw["recheck_owned"]()
        return {"status": "NATIVE_EGRESS_BOOT_RECEIPT_VERIFIED"}
    monkeypatch.setattr(native, "_prepare_boot_egress_locked", prepare)
    with native._locked(rootfd, 0) as statefd:
        def invoke():
            return native._prepare_owned_committed_boot_egress_locked(
                rootfd, statefd, distribution="debian", worker_uid=33,
                namespace_identity=(17, 29), profile_receipt_sha256="a"*64,
                executable_receipt_sha256="b"*64,
                recheck_namespace_owner=owned, allow_prepare=True)
        if fault == "none":
            result = invoke()
            assert result["generation_manifest_sha256"] == calls[0]
            assert result["committed_resources_verified"]
            assert not result["authorizes_nginx_activation"]
            assert not result["authorizes_catalog_publication"]
        else:
            with pytest.raises(native.NativeV2TransactionError):
                invoke()
            assert len(calls) == (0 if fault in ("pending", "orphan") else 1)
    if fault != "resource-drift":
        assert _fixture_resource_bytes(paths) == old


@pytest.mark.parametrize("fault", ["none", "empty", "type", "verify-only", "rollover", "drift"])
def test_committed_boot_resume_forwards_exact_receipt_and_generation_guard(
        filesystem, monkeypatch, fault):
    rootfd, _, _, _, _ = filesystem
    old = _owned_generation(active=False)
    paths = _owned_fixture_paths(filesystem, old)
    saved = b"exact retained intent"
    calls = []

    def prepare(root, state, rules, **kw):
        assert root == rootfd and state == statefd
        assert kw["expected_previous_receipt"] == saved
        assert kw["allow_prepare"] is True and kw["allow_boot_rollover"] is False
        assert kw["generation_manifest_sha256"] == hashlib.sha256(
            old[native._OWNED_MANIFEST]).hexdigest()
        calls.append("prepare")
        kw["recheck_owned"]()
        if fault == "drift":
            paths[native._OWNED_MAIN].write_bytes(b"foreign")
            kw["recheck_owned"]()
        return {"status": "NATIVE_EGRESS_BOOT_RECEIPT_VERIFIED"}

    monkeypatch.setattr(native, "_prepare_boot_egress_locked", prepare)
    with native._locked(rootfd, 0) as statefd:
        def invoke():
            return native._prepare_owned_committed_boot_egress_locked(
                rootfd, statefd, distribution="debian", worker_uid=33,
                namespace_identity=(17, 29), profile_receipt_sha256="a"*64,
                executable_receipt_sha256="b"*64, recheck_namespace_owner=lambda: None,
                allow_prepare=fault != "verify-only", allow_boot_rollover=fault == "rollover",
                expected_existing_receipt=b"" if fault == "empty" else
                "foreign type" if fault == "type" else saved)
        if fault == "none":
            assert invoke()["committed_resources_verified"] is True
        else:
            with pytest.raises(native.NativeV2TransactionError):
                invoke()
        assert calls == (["prepare"] if fault in ("none", "drift") else [])
    if fault != "drift":
        assert _fixture_resource_bytes(paths) == old


def test_committed_boot_egress_generation_recheck_expires(filesystem):
    rootfd, _, _, _, _ = filesystem
    old = _owned_bootstrap_resources()
    _owned_fixture_paths(filesystem, old)
    with native._locked(rootfd, 0) as statefd:
        with native._owned_committed_boot_egress_generation_locked(
                rootfd, statefd, distribution="debian", worker_uid=33,
        ) as (plan, recheck):
            assert plan["generation"] == 0
            recheck()
        with pytest.raises(native.NativeV2TransactionError, match="SCOPE_EXPIRED"):
            recheck()


@pytest.mark.parametrize("kind", ["bootstrap", "disabled", "active"])
@pytest.mark.parametrize("fault", ["none", "pending", "orphan", "intent", "owner", "drift"])
def test_fresh_boot_namespace_retains_committed_resources_before_creation(
        filesystem, monkeypatch, kind, fault):
    rootfd, state, _, _, _ = filesystem
    old = (_owned_bootstrap_resources() if kind == "bootstrap" else
           _owned_generation(active=kind == "active"))
    paths = _owned_fixture_paths(filesystem, old)
    if fault == "pending":
        (state / native._OWNED_WAL).write_bytes(b"pending")
        (state / native._OWNED_WAL).chmod(0o600)
    elif fault == "orphan":
        orphan = paths[native._OWNED_MAIN].parent / native._OWNED_STAGES[native._OWNED_MAIN]
        orphan.write_bytes(b"orphan")
        orphan.chmod(0o644)
    calls = []
    boot = "12345678-1234-1234-1234-123456789abc"

    def owner():
        if fault == "owner":
            raise native.NativeV2TransactionError("OWNER_CHANGED")

    def intent(got_state, rules, **kw):
        assert got_state == statefd
        if fault == "intent":
            raise native.NativeV2TransactionError("INTENT_REFUSED")
        return boot, None

    def create(*, recheck_owned):
        recheck_owned()
        calls.append("create")
        if fault == "drift":
            paths[native._OWNED_MAIN].write_bytes(b"foreign")
        recheck_owned()
        return {"boot_id": boot, "namespace_device": 17, "namespace_inode": 29,
                "loopback_only_observed": True, "empty_ruleset_observed": True}

    def prepare(got_root, got_state, rules, **kw):
        assert (got_root, got_state) == (rootfd, statefd)
        assert kw["namespace_identity"] == (17, 29)
        assert kw["generation"] == (0 if kind == "bootstrap" else 1)
        assert kw["allow_prepare"] and not kw["allow_boot_rollover"]
        assert kw["expected_previous_receipt"] is None
        kw["recheck_owned"]()
        calls.append("prepare")
        return {"boot_id": boot, "namespace_device": 17, "namespace_inode": 29}

    monkeypatch.setattr(native, "_fresh_boot_egress_intent_locked", intent)
    monkeypatch.setattr(native, "_create_fixed_loopback_namespace_locked", create)
    monkeypatch.setattr(native, "_prepare_boot_egress_locked", prepare)
    with native._locked(rootfd, 0) as statefd:
        def invoke():
            return native._create_owned_committed_boot_egress_locked(
                rootfd, statefd, distribution="debian", worker_uid=33,
                profile_receipt_sha256="a"*64, executable_receipt_sha256="b"*64,
                recheck_stopped_owner=owner)
        if kind != "active" and fault == "none":
            result = invoke()
            assert calls == ["create", "prepare"]
            assert result["committed_resources_verified"]
            assert not result["authorizes_nginx_activation"]
            assert not result["authorizes_catalog_publication"]
        else:
            with pytest.raises(native.NativeV2TransactionError):
                invoke()
            assert calls == (["create"] if kind != "active" and fault == "drift" else [])
    if kind == "active" or fault != "drift":
        assert _fixture_resource_bytes(paths) == old


@pytest.mark.parametrize("initial", [True, False])
@pytest.mark.parametrize("boundary", ["none", "catalog", "main", "include", "state", "manifest"])
def test_inactive_live_wal_prepare_preserves_wal_and_withdraws_catalog(
        filesystem, monkeypatch, initial, boundary):
    old = _owned_bootstrap_resources() if initial else _owned_generation(active=False)
    new = _owned_generation(1 if initial else 2,
                            previous=None if initial else json.loads(old[V2_STATE]),
                            active=False)
    paths = _owned_fixture_paths(filesystem, new)
    fd, state, _, _, events = filesystem
    wal = native._owned_wal_record(old, new, live=True)
    record = state / native._OWNED_WAL
    record.write_bytes(wal)
    record.chmod(0o600)
    inode = record.stat().st_ino
    target = {"catalog": native._CATALOG, "main": native._OWNED_MAIN,
              "include": native._INCLUDE, "state": V2_STATE,
              "manifest": native._OWNED_MANIFEST}.get(boundary)
    actual = native._owned_write_resource

    def interrupted(*args):
        actual(*args)
        if args[3] == target:
            assert record.read_bytes() == wal
            assert not paths[native._CATALOG].exists()
            raise _OwnedFixturePowerLoss()

    def unexpected(*args, **kwargs):
        pytest.fail("Inactive byte preparation reached runtime or publication")

    for name in ("_owned_live_observe", "_owned_live_validate",
                 "_owned_live_reload", "_owned_live_finish"):
        monkeypatch.setattr(native, name, unexpected)

    def prepare():
        with native._owned_fixture_layout(fd, recovering=True) as layout:
            return native._prepare_owned_inactive_wal_rollback_locked(
                *layout, distribution="debian", expected_wal=wal,
                recheck_stopped_owner=lambda: None)

    if boundary != "none":
        with monkeypatch.context() as m:
            m.setattr(native, "_owned_write_resource", interrupted)
            with pytest.raises(_OwnedFixturePowerLoss):
                prepare()
        assert record.read_bytes() == wal
        assert not paths[native._CATALOG].exists()
    result = prepare()
    assert result["status"] == "OWNED_INACTIVE_WAL_PRIOR_BYTES_PREPARED"
    assert result["wal_sha256"] == hashlib.sha256(wal).hexdigest()
    assert result["prior_generation"] == (None if initial else 1)
    assert result["catalog_withdrawn"] and result["recovery_required"]
    assert not result["runtime_verified"]
    assert not result["authorizes_nginx_activation"]
    assert not result["authorizes_catalog_publication"]
    assert _fixture_resource_bytes(paths) == {**old, native._CATALOG: None}
    assert record.read_bytes() == wal and record.stat().st_ino == inode
    assert prepare() == result
    assert not events


@pytest.mark.parametrize("fault", ["active-prior", "v2", "unpublished",
                                    "foreign-target", "foreign-stage",
                                    "changed-wal", "stopped-owner"])
def test_inactive_live_wal_prepare_refuses_before_target_effects(
        filesystem, fault):
    old = _owned_generation(active=fault == "active-prior")
    new = _owned_generation(2, previous=json.loads(old[V2_STATE]), active=False)
    paths = _owned_fixture_paths(filesystem, new)
    fd, state, _, _, events = filesystem
    wal = native._owned_wal_record(old, new, live=fault != "v2")
    record = state / (native._OWNED_WAL_TMP if fault == "unpublished" else native._OWNED_WAL)
    record.write_bytes(wal)
    record.chmod(0o600)
    if fault == "foreign-target":
        paths[native._INCLUDE].write_bytes(b"foreign")
    if fault == "foreign-stage":
        stage = paths[native._INCLUDE].parent / native._OWNED_STAGES[native._INCLUDE]
        stage.write_bytes(b"foreign")
        stage.chmod(0o644)
    before = _fixture_resource_bytes(paths)

    def stopped():
        if fault == "stopped-owner":
            raise native.NativeV2TransactionError("OWNER_CHANGED")

    with native._owned_fixture_layout(fd, recovering=True) as layout:
        with pytest.raises(native.NativeV2TransactionError):
            native._prepare_owned_inactive_wal_rollback_locked(
                *layout, distribution="debian",
                expected_wal=b"changed" if fault == "changed-wal" else wal,
                recheck_stopped_owner=stopped)
    assert _fixture_resource_bytes(paths) == before
    assert record.read_bytes() == wal
    if fault == "foreign-stage":
        assert stage.read_bytes() == b"foreign"
    assert not events


@pytest.mark.parametrize("fault", ["none", "pre-health", "post-health", "owner-drift",
                                    "catalog-drift", "wal-unlink"])
def test_finish_inactive_wal_requires_prior_runtime_and_exact_publication(
        filesystem, monkeypatch, fault):
    old = _owned_generation(active=False)
    new = _owned_generation(2, previous=json.loads(old[V2_STATE]), active=False)
    withdrawn = {**old, native._CATALOG: None}
    paths = _owned_fixture_paths(filesystem, withdrawn)
    root, state, _, _, _ = filesystem
    wal = native._owned_wal_record(old, new, live=True)
    record = state / native._OWNED_WAL
    record.write_bytes(wal)
    record.chmod(0o600)
    events = []
    identity = (123, (1, 2))
    context = ({}, 1, "a"*64)

    def observe(fd, *, expected_unit):
        assert fd == root and expected_unit == b"signed"
        return identity

    def validate(fd, state_fd, resources):
        assert fd == root and resources == old
        return context

    def health(fd, observed, checked, catalog, *, publish, expected_unit):
        assert (fd, observed, checked, expected_unit) == (root, identity, context, b"signed")
        assert record.read_bytes() == wal
        assert _fixture_resource_bytes(paths) == (old if publish else withdrawn)
        assert catalog == (old[native._CATALOG] if publish else None)
        events.append(publish)
        if fault == "pre-health" and not publish:
            raise native.NativeV2TransactionError("PRE_HEALTH")
        if fault == "post-health" and publish:
            raise native.NativeV2TransactionError("POST_HEALTH")
        if fault == "catalog-drift" and publish:
            paths[native._CATALOG].write_bytes(b"foreign")
            raise native.NativeV2TransactionError("CATALOG_CHANGED")

    def owner():
        if fault == "owner-drift" and paths[native._CATALOG].exists():
            raise native.NativeV2TransactionError("OWNER_CHANGED")

    monkeypatch.setattr(native, "_owned_live_observe", observe)
    monkeypatch.setattr(native, "_owned_live_validate", validate)
    monkeypatch.setattr(native, "_owned_live_health_bound", health)
    if fault == "wal-unlink":
        actual_unlink = native._unlink_known

        def unlink(*args):
            actual_unlink(*args)
            if args[1] == native._OWNED_WAL:
                raise OSError("uncertain fsync after WAL unlink")
        monkeypatch.setattr(native, "_unlink_known", unlink)

    with native._owned_fixture_layout(root, recovering=True) as layout:
        def finish():
            return native._finish_owned_inactive_wal_rollback_locked(
                root, *layout, distribution="debian", expected_wal=wal,
                expected_unit=b"signed", recheck_active_owner=owner)
        if fault == "none":
            assert finish() == {
                "status": "OWNED_INACTIVE_WAL_ROLLBACK_OBSERVED",
                "prior_generation": 1, "recovery_required": False,
            }
        else:
            with pytest.raises((native.NativeV2TransactionError, OSError)):
                finish()

    if fault in ("none", "wal-unlink"):
        assert _fixture_resource_bytes(paths) == old and not record.exists()
    elif fault == "catalog-drift":
        assert paths[native._CATALOG].read_bytes() == b"foreign"
        assert record.read_bytes() == wal
    else:
        assert _fixture_resource_bytes(paths) == withdrawn and record.read_bytes() == wal
    assert events == ([False] if fault in ("pre-health", "owner-drift") else [False, True])


@pytest.mark.parametrize("kind", ["bootstrap", "disabled", "active"])
@pytest.mark.parametrize("fault", ["none", "missing-wal", "v2", "orphan",
                                    "unprepared", "owner", "wal-drift", "resource-drift"])
def test_prepared_wal_boot_namespace_requires_exact_prior_and_keeps_catalog_withdrawn(
        filesystem, monkeypatch, kind, fault):
    rootfd, state, _, _, _ = filesystem
    old = (_owned_bootstrap_resources() if kind == "bootstrap" else
           _owned_generation(active=kind == "active"))
    new = _owned_generation(1 if kind == "bootstrap" else 2,
                            previous=None if kind == "bootstrap" else json.loads(old[V2_STATE]),
                            active=False)
    withdrawn = {**old, native._CATALOG: None}
    current = new if fault == "unprepared" else withdrawn
    paths = _owned_fixture_paths(filesystem, current)
    wal = native._owned_wal_record(old, new, live=fault != "v2")
    record = state / native._OWNED_WAL
    if fault != "missing-wal":
        record.write_bytes(wal)
        record.chmod(0o600)
    if fault == "orphan":
        orphan = paths[native._OWNED_MAIN].parent / native._OWNED_STAGES[native._OWNED_MAIN]
        orphan.write_bytes(b"foreign")
        orphan.chmod(0o644)
    calls = []
    boot = "12345678-1234-1234-1234-123456789abc"

    def owner():
        if fault == "owner":
            raise native.NativeV2TransactionError("OWNER_CHANGED")

    def intent(got_state, rules, **kw):
        assert got_state == statefd and "8.8.8.8" not in rules
        assert kw["generation"] == (0 if kind == "bootstrap" else 1)
        if kind != "bootstrap":
            assert kw["generation_manifest_sha256"] == hashlib.sha256(
                old[native._OWNED_MANIFEST]).hexdigest()
        return boot, b"prior receipt"

    def create(*, recheck_owned):
        recheck_owned()
        calls.append("create")
        if fault == "wal-drift":
            record.write_bytes(b"foreign")
        if fault == "resource-drift":
            paths[native._OWNED_MAIN].write_bytes(b"foreign")
        recheck_owned()
        return {"boot_id": boot, "namespace_device": 17, "namespace_inode": 29,
                "loopback_only_observed": True, "empty_ruleset_observed": True}

    def prepare(got_root, got_state, rules, **kw):
        assert (got_root, got_state) == (rootfd, statefd)
        assert kw["namespace_identity"] == (17, 29)
        assert kw["expected_previous_receipt"] == b"prior receipt"
        assert kw["allow_boot_rollover"] and kw["allow_prepare"]
        kw["recheck_owned"]()
        calls.append("prepare")
        return {"boot_id": boot, "namespace_device": 17, "namespace_inode": 29}

    monkeypatch.setattr(native, "_fresh_boot_egress_intent_locked", intent)
    monkeypatch.setattr(native, "_create_fixed_loopback_namespace_locked", create)
    monkeypatch.setattr(native, "_prepare_boot_egress_locked", prepare)
    with native._locked(rootfd, 0) as statefd:
        def invoke():
            return native._create_owned_prepared_wal_boot_egress_locked(
                rootfd, statefd, distribution="debian", worker_uid=33,
                expected_wal=wal, profile_receipt_sha256="a"*64,
                executable_receipt_sha256="b"*64, recheck_stopped_owner=owner,
                allow_boot_rollover=True)
        if kind != "active" and fault == "none":
            result = invoke()
            assert calls == ["create", "prepare"]
            assert result["prior_resources_verified"] and result["recovery_required"]
            assert result["catalog_withdrawn"]
            assert result["wal_sha256"] == hashlib.sha256(wal).hexdigest()
            assert "committed_resources_verified" not in result
            assert not result["authorizes_nginx_activation"]
            assert not result["authorizes_catalog_publication"]
        else:
            with pytest.raises(native.NativeV2TransactionError):
                invoke()
            assert calls == (["create"] if kind != "active" and fault in
                             ("wal-drift", "resource-drift") else [])
    if fault == "missing-wal":
        assert not record.exists()
    else:
        assert record.read_bytes() == (b"foreign" if calls and fault == "wal-drift" else wal)
    if not (calls and fault == "resource-drift"):
        assert _fixture_resource_bytes(paths) == current


def test_prepared_wal_boot_egress_scope_expires(filesystem):
    rootfd, state, _, _, _ = filesystem
    old = _owned_bootstrap_resources()
    new = _owned_generation(active=False)
    _owned_fixture_paths(filesystem, old)
    wal = native._owned_wal_record(old, new, live=True)
    record = state / native._OWNED_WAL
    record.write_bytes(wal)
    record.chmod(0o600)
    with native._locked(rootfd, 0) as statefd:
        with native._owned_prepared_wal_boot_egress_generation_locked(
                rootfd, statefd, distribution="debian", worker_uid=33,
                expected_wal=wal) as (plan, recheck):
            assert plan["generation"] == 0
            recheck()
        with pytest.raises(native.NativeV2TransactionError, match="SCOPE_EXPIRED"):
            recheck()


@pytest.mark.parametrize("fault", ["none", "wrong-namespace", "owner-drift", "catalog-drift"])
def test_verify_prepared_wal_boot_egress_never_prepares_or_publishes(
        filesystem, monkeypatch, fault):
    rootfd, state, _, _, _ = filesystem
    old = _owned_generation(active=False)
    new = _owned_generation(2, previous=json.loads(old[V2_STATE]), active=False)
    withdrawn = {**old, native._CATALOG: None}
    paths = _owned_fixture_paths(filesystem, withdrawn)
    wal = native._owned_wal_record(old, new, live=True)
    record = state / native._OWNED_WAL
    record.write_bytes(wal)
    record.chmod(0o600)
    calls = []

    def stopped():
        if calls and fault == "owner-drift":
            raise native.NativeV2TransactionError("OWNER_CHANGED")

    def verify(got_root, got_state, rules, **kw):
        assert (got_root, got_state) == (rootfd, statefd)
        assert kw["namespace_identity"] == (17, 29)
        assert not kw["allow_prepare"] and not kw["allow_boot_rollover"]
        assert kw["generation"] == 1
        assert kw["generation_manifest_sha256"] == hashlib.sha256(
            old[native._OWNED_MANIFEST]).hexdigest()
        calls.append("verify")
        if fault == "wrong-namespace":
            raise native.NativeV2TransactionError("WRONG_NAMESPACE")
        if fault == "catalog-drift":
            paths[native._CATALOG].write_bytes(b"foreign")
        kw["recheck_owned"]()
        return {"status": "NATIVE_EGRESS_BOOT_RECEIPT_VERIFIED"}

    monkeypatch.setattr(native, "_prepare_boot_egress_locked", verify)
    with native._locked(rootfd, 0) as statefd:
        def invoke():
            return native._verify_owned_prepared_wal_boot_egress_locked(
                rootfd, statefd, distribution="debian", worker_uid=33,
                expected_wal=wal, namespace_identity=(17, 29),
                profile_receipt_sha256="a"*64, executable_receipt_sha256="b"*64,
                recheck_stopped_owner=stopped)
        if fault == "none":
            result = invoke()
            assert result["prior_resources_verified"] and result["recovery_required"]
            assert result["catalog_withdrawn"]
            assert not result["authorizes_nginx_activation"]
            assert not result["authorizes_catalog_publication"]
        else:
            with pytest.raises(native.NativeV2TransactionError):
                invoke()
    assert calls == ["verify"]
    assert record.read_bytes() == wal
    if fault == "catalog-drift":
        assert paths[native._CATALOG].read_bytes() == b"foreign"
    else:
        assert _fixture_resource_bytes(paths) == withdrawn


@pytest.mark.parametrize("fault", ["none", "namespace", "owner", "listener", "child"])
def test_dedicated_health_binds_listener_before_and_after_fixed_child(monkeypatch, fault):
    from contextlib import contextmanager
    from repocache import server_native_egress_candidate_v1 as egress
    from repocache import server_native_nginx_effective_unit_v1 as unit
    calls = []
    context = (None, None, None)
    expected = {"main_pid_observed": 123, "private_unit_identity": (31, 41)}
    namespace = (17, 29)

    @contextmanager
    def scope():
        yield 11, namespace if fault != "namespace" else (17, 30), lambda: None

    def owned():
        if fault == "owner" and "child" in calls:
            raise native.NativeV2TransactionError("OWNER_CHANGED")

    def observe(**kw):
        assert kw == {"https_port": 8008, "namespace_identity": namespace,
                      "executable_identity": (51, 61)}
        return expected

    def listener(identity, got_context, reobserve, *, namespace_identity):
        assert identity == (123, (31, 41)) and got_context == context
        assert namespace_identity == namespace and reobserve() == identity
        calls.append("listener")
        return 78 if fault == "listener" and "child" in calls else 77

    def child(net, identity, got_context, catalog, *, publish):
        assert (net, identity, got_context, catalog, publish) == (11, namespace, context, None, False)
        calls.append("child")
        if fault == "child":
            raise native.NativeV2TransactionError("CHILD_FAILED")

    monkeypatch.setattr(native, "_verify_current_root_fd", lambda fd: None)
    monkeypatch.setattr(egress, "_fixed_namespace_scope", scope)
    monkeypatch.setattr(unit, "_inspect_signed_owned_namespace_runtime", observe)
    monkeypatch.setattr(native, "_owned_master_listener", listener)
    monkeypatch.setattr(native, "_run_dedicated_health_child", child)
    def invoke():
        return native._owned_dedicated_live_health_bound(
            10, context, None, publish=False, namespace_identity=namespace,
            executable_identity=(51, 61), recheck_owned=owned)
    if fault == "none":
        result = invoke()
        assert result["status"] == "OWNED_DEDICATED_HEALTH_OBSERVED"
        assert result["listener_inode"] == 77
        assert not result["authorizes_nginx_activation"]
        assert not result["authorizes_catalog_publication"]
        assert calls == ["listener", "child", "listener"]
    else:
        with pytest.raises(native.NativeV2TransactionError):
            invoke()
        assert calls == {"namespace": [], "owner": ["listener", "child"],
                         "listener": ["listener", "child", "listener"],
                         "child": ["listener", "child"]}[fault]


@pytest.mark.parametrize("exit_status", [0, 256])
def test_dedicated_health_parent_reaps_only_fixed_child(monkeypatch, exit_status):
    import signal
    import threading
    from types import SimpleNamespace
    calls = []
    monkeypatch.setattr(threading, "active_count", lambda: 1)
    monkeypatch.setattr(signal, "getsignal", lambda signum: signal.SIG_DFL)
    monkeypatch.setattr(native, "os", SimpleNamespace(
        listdir=lambda path: ["1"], setns=lambda *args: None, CLONE_NEWNET=1,
        fork=lambda: 123, WNOHANG=1, WIFEXITED=lambda status: True,
        WEXITSTATUS=lambda status: status >> 8,
        waitpid=lambda pid, mode: calls.append((pid, mode)) or (pid, exit_status)))
    def invoke():
        native._run_dedicated_health_child(11, (17, 29), (None, None, None), None,
                                          publish=False)
    if exit_status:
        with pytest.raises(native.NativeV2TransactionError, match="HEALTH_UNVERIFIED"):
            invoke()
    else:
        invoke()
    assert calls == [(123, 1)]


@pytest.mark.parametrize("fault", ["none", "missing-receipt", "owner", "receipt-race", "catalog-drift"])
def test_resume_prepared_wal_boot_egress_requires_existing_exact_receipt(
        filesystem, monkeypatch, fault):
    rootfd, state, _, _, _ = filesystem
    old = _owned_generation(active=False)
    new = _owned_generation(2, previous=json.loads(old[V2_STATE]), active=False)
    withdrawn = {**old, native._CATALOG: None}
    paths = _owned_fixture_paths(filesystem, withdrawn)
    wal = native._owned_wal_record(old, new, live=True)
    record = state / native._OWNED_WAL
    record.write_bytes(wal)
    record.chmod(0o600)
    calls = []

    def stopped():
        if fault == "owner":
            raise native.NativeV2TransactionError("OWNER_CHANGED")

    def receipt(got_state, owner, group):
        assert (got_state, owner, group) == (statefd, 0, 0)
        return None if fault == "missing-receipt" else b"exact prior intent"

    def prepare(got_root, got_state, rules, **kw):
        assert (got_root, got_state) == (rootfd, statefd)
        assert kw["namespace_identity"] == (17, 29)
        assert kw["allow_prepare"] and not kw["allow_boot_rollover"]
        assert kw["expected_previous_receipt"] == b"exact prior intent"
        assert kw["generation"] == 1
        calls.append("prepare")
        if fault == "receipt-race":
            raise native.NativeV2TransactionError("RECEIPT_CHANGED")
        if fault == "catalog-drift":
            paths[native._CATALOG].write_bytes(b"foreign")
        kw["recheck_owned"]()
        return {"status": "NATIVE_EGRESS_BOOT_RECEIPT_VERIFIED"}

    monkeypatch.setattr(native, "_read_boot_egress_receipt", receipt)
    monkeypatch.setattr(native, "_prepare_boot_egress_locked", prepare)
    with native._locked(rootfd, 0) as statefd:
        def invoke():
            return native._resume_owned_prepared_wal_boot_egress_locked(
                rootfd, statefd, distribution="debian", worker_uid=33,
                expected_wal=wal, namespace_identity=(17, 29),
                profile_receipt_sha256="a"*64, executable_receipt_sha256="b"*64,
                recheck_stopped_owner=stopped)
        if fault == "none":
            result = invoke()
            assert result["recovery_required"] and result["catalog_withdrawn"]
            assert not result["authorizes_nginx_activation"]
            assert not result["authorizes_catalog_publication"]
        else:
            with pytest.raises(native.NativeV2TransactionError):
                invoke()
    assert calls == ([] if fault in ("owner", "missing-receipt") else ["prepare"])
    assert record.read_bytes() == wal
    if fault == "catalog-drift":
        assert paths[native._CATALOG].read_bytes() == b"foreign"
    else:
        assert _fixture_resource_bytes(paths) == withdrawn


@pytest.mark.parametrize("fault", ["timeout", "reaped", "thread", "handler"])
def test_dedicated_health_child_timeout_and_preflight_do_not_signal_foreign_pid(
        monkeypatch, fault):
    import signal
    import threading
    from types import SimpleNamespace
    calls = []
    monkeypatch.setattr(threading, "active_count", lambda: 2 if fault == "thread" else 1)
    monkeypatch.setattr(signal, "getsignal",
                        lambda signum: signal.SIG_IGN if fault == "handler" else signal.SIG_DFL)
    times = iter([0, 46])
    monkeypatch.setattr(native, "time", SimpleNamespace(monotonic=lambda: next(times)))
    def fork():
        calls.append("fork")
        return 123
    def wait(pid, mode):
        assert pid == 123
        calls.append(("wait", mode))
        if fault == "reaped" and calls.count(("wait", 1)) == 2:
            raise ChildProcessError
        return 0, 0
    def kill(pid, sig):
        assert (pid, sig) == (123, signal.SIGKILL)
        calls.append("kill")
    monkeypatch.setattr(native, "os", SimpleNamespace(
        listdir=lambda path: ["1"], setns=lambda *args: None, CLONE_NEWNET=1,
        fork=fork, WNOHANG=1, waitpid=wait, kill=kill))
    with pytest.raises(native.NativeV2TransactionError):
        native._run_dedicated_health_child(11, (17, 29), (None, None, None), None,
                                          publish=False)
    if fault == "timeout":
        assert calls == ["fork", ("wait", 1), ("wait", 1), "kill", ("wait", 0)]
    elif fault == "reaped":
        assert calls == ["fork", ("wait", 1), ("wait", 1)]
    else:
        assert not calls


@pytest.mark.parametrize("prepared", [False, True])
@pytest.mark.parametrize("fault", ["none", "active-route", "nonloopback", "pending",
                                    "policy", "policy-drift", "storage-drift", "scratch-drift", "scratch-service",
                                    "enabled", "start", "health",
                                    "foreign-master", "generation-drift", "selected-drift"])
def test_committed_dedicated_start_is_fixed_and_compensates_only_owned_master(
        filesystem, monkeypatch, fault, prepared):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from repocache import server_native_nginx_effective_unit_v1 as unit
    from repocache import server_native_installed_storage_v1 as storage
    from repocache import server_root_control_host_preflight_v1 as host

    rootfd, state, _, _, _ = filesystem
    cfg = document(1, generation=1)
    cfg["deployment"]["paths"]["generated_include"] = native._OWNED_INCLUDE_PATH
    cfg["deployment"]["listen"]["bind_address"] = (
        "0.0.0.0" if fault == "nonloopback" else "127.0.0.1")
    cfg["repositories"][0]["desired_state"] = "active" if fault == "active-route" else "disabled"
    raw = _canon(snapshot(generation=1, doc=cfg))
    main, include, catalog = native._render_owned_managed_candidate(
        cfg, 1, "almalinux",
        {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}} if fault == "active-route" else {})
    resources = {V2_STATE: raw, native._OWNED_MAIN: main, native._INCLUDE: include,
                 native._CATALOG: catalog, native._OWNED_MANIFEST:
                     native._owned_manifest_for(raw, main, include, catalog)}
    wal = None
    if prepared:
        next_cfg = {**cfg, "expected_state_generation": 2}
        next_raw = _canon(snapshot(generation=2, previous=json.loads(raw), doc=next_cfg))
        next_main, next_include, next_catalog = native._render_owned_managed_candidate(
            next_cfg, 2, "almalinux",
            {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}} if fault == "active-route" else {})
        new = {V2_STATE: next_raw, native._OWNED_MAIN: next_main,
               native._INCLUDE: next_include, native._CATALOG: next_catalog,
               native._OWNED_MANIFEST:
                   native._owned_manifest_for(next_raw, next_main, next_include, next_catalog)}
        wal = native._owned_wal_record(resources, new, live=True)
        resources = {**resources, native._CATALOG: None}
    paths = _owned_fixture_paths(filesystem, resources)
    if fault == "pending" or prepared:
        pending = state / native._OWNED_WAL
        pending.write_bytes(b"existing pending evidence" if fault == "pending" else wal)
        pending.chmod(0o600)
    calls = []
    running = False
    foreign = False
    policy_reads = 0
    storage_reads = 0
    scratch_reads = 0
    ns, exe = (17, 29), (31, 41)

    # Retain the real layout before replacing its public test seam, so
    # nested fixture calls cannot accidentally recurse into the mock.
    real_layout = native._owned_layout_locked

    @contextmanager
    def layout(root, statefd, *, recovering):
        assert root == rootfd and recovering == prepared
        with native._locked(rootfd, 0) as locked_state:
            with real_layout(rootfd, locked_state, recovering=recovering) as result:
                yield result

    def observe(*, https_port, active):
        if active != running:
            raise unit.EffectiveNginxUnitError("WRONG_STATE")
        return {"main_pid_observed": 123 if active else 0,
                "private_unit_identity": (51, 61),
                "private_dropin_identity": (71, 81)}

    def runtime(*, https_port, namespace_identity, executable_identity):
        assert namespace_identity == ns and executable_identity == exe
        assert running
        result = observe(https_port=https_port, active=True)
        if foreign:
            result["private_unit_identity"] = (51, 62)
        return result

    def command(argv, **kwargs):
        nonlocal running
        assert argv[0] == native._SYSTEMCTL and argv[2] == native._OWNED_WAL_DOMAIN
        assert not kwargs["shell"]
        if argv[1] == "is-enabled":
            return SimpleNamespace(returncode=0 if fault == "enabled" else 1,
                                   stdout=b"enabled\n" if fault == "enabled" else b"disabled\n")
        calls.append(argv[1])
        if argv[1] == "start":
            running = True
            return SimpleNamespace(returncode=1 if fault == "start" else 0)
        assert argv[1] == "stop" and running
        running = False
        return SimpleNamespace(returncode=0)

    def policy(root, statefd, rules, **kwargs):
        nonlocal policy_reads
        policy_reads += 1
        assert not kwargs["allow_prepare"] and not kwargs["allow_boot_rollover"]
        assert kwargs["namespace_identity"] == ns
        kwargs["recheck_owned"]()
        if fault == "policy":
            raise native.NativeV2TransactionError("POLICY_REFUSED")
        digest = "b" if fault == "policy-drift" and policy_reads >= 2 else "a"
        return {"receipt_sha256": digest*64}

    def inspect_storage(*args, **kwargs):
        nonlocal storage_reads
        storage_reads += 1
        assert not kwargs["allow_create"]
        if fault == "storage-drift" and storage_reads >= 2:
            return {"repository_cache_roots_verified": [], "changed": True}
        return {"repository_cache_roots_verified": []}

    def health(root, context, catalog_bytes, **kwargs):
        nonlocal foreign
        assert running and catalog_bytes == (None if prepared else catalog)
        assert kwargs["publish"] == (not prepared)
        assert kwargs.get("require_withdrawn", False) == prepared
        kwargs["recheck_owned"]()
        calls.append("health")
        if fault == "generation-drift":
            paths[native._CATALOG].write_bytes(b"foreign catalog")
            raise native.NativeV2TransactionError("GENERATION_CHANGED")
        if fault in ("health", "foreign-master"):
            foreign = fault == "foreign-master"
            raise native.NativeV2TransactionError("TLS_REFUSED")
        return {"main_pid": 123, "catalog_observed": not prepared, "generation": 1,
                "listener_inode": 1234, "authorizes_nginx_activation": False,
                "authorizes_catalog_publication": False}

    monkeypatch.setattr(host, "require_native_host_preconditions", lambda: {})
    monkeypatch.setattr(native, "_verify_current_root_fd", lambda root: None)
    monkeypatch.setattr(native, "_require_audited_native_package_for_activation", lambda *a, **kw: None)
    monkeypatch.setattr(native, "_owned_layout_locked", layout)
    monkeypatch.setattr(native, "_verify_tls_pair", lambda *a, **kw: "c"*64)
    monkeypatch.setattr(native, "_prepare_boot_egress_locked", policy)
    monkeypatch.setattr(native, "_owned_dedicated_live_health_bound", health)
    monkeypatch.setattr(unit, "inspect_signed_owned_namespace_unit", observe)
    monkeypatch.setattr(unit, "_inspect_signed_owned_namespace_runtime", runtime)
    monkeypatch.setattr(unit, "_safe_native_systemctl", lambda: None)
    monkeypatch.setattr(native.subprocess, "run", command)
    monkeypatch.setattr(storage, "prepare_dedicated_candidate_storage", inspect_storage)
    def inspect_scratch(*args, **kwargs):
        nonlocal scratch_reads
        scratch_reads += 1
        assert kwargs["dedicated"] and not kwargs.get("allow_create", False)
        inode = 3 if fault == "scratch-drift" and scratch_reads >= 2 else 2
        return ((1,), {"scratch": (inode,)})
    monkeypatch.setattr(native, "_owned_alma_runtime_temps", inspect_scratch)
    def service_scratch(pid, expected):
        assert running and pid == 123 and expected == ((1,), {"scratch": (2,)})
        if fault == "scratch-service":
            raise native.NativeV2TransactionError("SCRATCH_MOUNT_REFUSED")
    monkeypatch.setattr(native, "_verify_owned_alma_runtime_service_view", service_scratch)
    monkeypatch.setattr(native, "verify_service_storage_mounts", lambda pid: None)
    monkeypatch.setattr(native.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=33))
    # The fixture already has an owned lock; the mocked layout is the
    # existing descriptor-only fixture and no real systemctl runs.
    def invoke():
        entry = (native._start_owned_prepared_wal_dedicated_locked if prepared else
                 native._start_owned_committed_dedicated_locked)
        return entry(
            rootfd, 0, namespace_identity=ns, executable_identity=exe,
            **({"expected_wal": wal, "expected_stopped": (
                {"main_pid_observed": 0, "private_unit_identity": (51, 62),
                 "private_dropin_identity": (71, 81)} if fault == "selected-drift" else None)}
                if prepared else {}),
            profile_receipt_sha256="a"*64, executable_receipt_sha256="b"*64,
            recheck_authenticated_owner=lambda: None)
    if fault == "selected-drift" and not prepared:
        pytest.skip("Only the composed prepared-WAL path supplies the stopped identity")
    if fault == "none":
        result = invoke()
        assert result["status"] == ("OWNED_DEDICATED_PREPARED_WAL_START_OBSERVED" if prepared
                                    else "OWNED_DEDICATED_COMMITTED_START_OBSERVED")
        if prepared:
            assert result["catalog_withdrawn"] and result["recovery_required"]
            assert result["wal_sha256"] == hashlib.sha256(wal).hexdigest()
            assert not result["catalog_observed"]
        assert result["service_storage_mounts_verified"]
        assert result["service_scratch_mounts_verified"]
        assert not result["enablement_changed"]
        assert calls == ["start", "health"] and running
    else:
        with pytest.raises(native.NativeV2TransactionError):
            invoke()
        assert calls == {"active-route": [], "nonloopback": [], "pending": [],
                         "policy": [], "policy-drift": [], "storage-drift": [], "scratch-drift": [],
                         "enabled": [], "selected-drift": [],
                         "start": ["start", "stop"], "health": ["start", "health", "stop"],
                         "scratch-service": ["start", "health", "stop"],
                         "foreign-master": ["start", "health"],
                         "generation-drift": ["start", "health"]}[fault]
        assert running == (fault in ("foreign-master", "generation-drift"))
    if fault == "policy-drift":
        assert policy_reads == 2
    if fault == "storage-drift":
        assert storage_reads == 2
    if fault == "scratch-drift":
        assert scratch_reads == 2
    expected = ({**resources, native._CATALOG: b"foreign catalog"}
                if fault == "generation-drift" else resources)
    assert _fixture_resource_bytes(paths) == expected
    if fault == "pending" or prepared:
        assert pending.read_bytes() == (b"existing pending evidence" if fault == "pending" else wal)



@pytest.mark.parametrize("dedicated", [False, True])
@pytest.mark.parametrize("fault", ["fresh", "repeat", "missing", "parent-mode",
                                   "parent-label", "child-label", "symlink", "mode",
                                   "owner", "group", "xattr", "nonempty", "extra",
                                   "preflight-all", "permissive"])
def test_alma_runtime_scratch_fresh_only_and_exact_identity(tmp_path, monkeypatch,
                                                          dedicated, fault):
    """Real dirfds/modes/ownership, synthetic SELinux xattr seam only."""
    from types import SimpleNamespace

    runtime = tmp_path / "run/repocache-nginx"
    runtime.mkdir(parents=True, mode=0o755)
    runtime.chmod(0o755)
    names = sorted(name for _, name in native._OWNED_RUNTIME_TEMP_NAMES)
    parent_type = b"repocache_nginx_pid_t" if dedicated else b"var_run_t"
    child_type = b"repocache_nginx_rw_t" if dedicated else b"httpd_var_run_t"
    def context(kind):
        return b"system_u:object_r:" + kind + b":s0\x00"
    labels = {runtime.stat().st_ino: context(parent_type)}
    writes = []
    if fault != "fresh":
        for name in names:
            leaf = runtime / name
            leaf.mkdir(mode=0o700)
            os.chown(leaf, 33, 0)
            labels[leaf.stat().st_ino] = context(child_type)
    first, last = runtime / names[0], runtime / names[-1]
    if fault == "missing":
        first.rmdir()
    elif fault == "parent-mode":
        runtime.chmod(0o775)
    elif fault == "parent-label":
        labels[runtime.stat().st_ino] = context(b"var_t")
    elif fault in ("child-label", "preflight-all"):
        labels[last.stat().st_ino] = context(b"httpd_cache_t")
        if fault == "preflight-all":
            first.rmdir()
    elif fault == "symlink":
        first.rmdir()
        first.symlink_to(tmp_path, target_is_directory=True)
    elif fault == "mode":
        first.chmod(0o750)
    elif fault == "owner":
        os.chown(first, 65534, 0)
    elif fault == "group":
        os.chown(first, 33, 33)
    elif fault == "nonempty":
        (first / "retain").write_bytes(b"foreign")
    elif fault == "extra":
        (runtime / "foreign").mkdir()

    def inode(fd):
        return os.fstat(fd).st_ino
    def listxattr(fd):
        return (["security.selinux", "user.foreign"] if
                fault == "xattr" and inode(fd) == first.stat().st_ino else
                ["security.selinux"])
    def getxattr(fd, name):
        assert name == "security.selinux"
        return labels.get(inode(fd), context(parent_type))
    def setxattr(fd, name, value):
        assert name == "security.selinux" and value == context(child_type)
        assert os.fstat(fd).st_uid == 0
        labels[inode(fd)] = value
        writes.append(inode(fd))

    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with monkeypatch.context() as patch:
            def policy(distribution, *, dedicated):
                assert distribution == "almalinux"
                if fault == "permissive":
                    raise native.InstalledStorageError("SELINUX_NOT_ENFORCING")
                return SimpleNamespace(finish=lambda: None)
            patch.setattr(native, "_Labels", policy)
            patch.setattr(native.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=33))
            patch.setattr(native.os, "listxattr", listxattr)
            patch.setattr(native.os, "getxattr", getxattr)
            patch.setattr(native.os, "setxattr", setxattr)
            def observe(create=False, require_all=True):
                return native._owned_alma_runtime_temps(
                    fd, dedicated=dedicated, allow_create=create,
                    require_all=require_all, inactive=True)
            if fault in ("fresh", "repeat"):
                result = observe(create=True)
                assert set(result[1]) == set(names)
                assert len(writes) == (5 if fault == "fresh" else 0)
                assert observe() == observe(create=True) == result
                assert len(writes) == (5 if fault == "fresh" else 0)
                for name in names:
                    assert (runtime / name).stat().st_uid == 33
                    assert result[1][name][-1] == context(child_type).rstrip(b"\x00")
            elif fault == "missing":
                assert len(observe(require_all=False)[1]) == 4
                with pytest.raises(native.NativeV2TransactionError,
                                   match="OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED"):
                    observe()
                assert not first.exists() and not writes
            else:
                with pytest.raises(native.NativeV2TransactionError,
                                   match="OWNED_CONTEXT_RUNTIME_TEMP_UNVERIFIED"):
                    observe(create=True)
                assert not writes
                if fault == "preflight-all":
                    assert not first.exists()
    finally:
        os.close(fd)


@pytest.mark.parametrize("status", [404, 200, 403, 301, 500])
def test_dedicated_withdrawn_catalog_requires_fresh_pinned_tls_404(monkeypatch, status):
    doc = document(1)
    leaf = "a" * 64
    calls = []
    def request(got_doc, path, maximum, *, expected_leaf_sha256):
        assert got_doc is doc and expected_leaf_sha256 == leaf
        calls.append((path, maximum))
        return f"HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n".encode("ascii")
    monkeypatch.setattr(native, "_fixed_https_get", request)
    if status == 404:
        native._require_dedicated_catalog_withdrawn((doc, 1, leaf))
    else:
        with pytest.raises(native.NativeV2TransactionError, match="WITHDRAWAL_UNVERIFIED"):
            native._require_dedicated_catalog_withdrawn((doc, 1, leaf))
    assert calls == [("/.well-known/repocache/catalog.json", 8192)]


@pytest.mark.parametrize("fault", ["none", "wrong-wal", "pre-health", "post-health",
                                   "listener", "owner-drift", "foreign-catalog",
                                   "wal-lost", "policy-drift", "active-route",
                                   "published-retry", "published-bad-label",
                                   "published-owner-drift", "published-wal-lost",
                                   "published-pre-health", "initial-foreign-catalog"])
def test_dedicated_wal_finalization_publishes_only_verified_prior(
        filesystem, monkeypatch, fault):
    """Real owned WAL/resource filesystem; mocked runtime and policy only."""
    from types import SimpleNamespace
    from repocache import server_native_nginx_effective_unit_v1 as unit
    from repocache import server_native_installed_storage_v1 as storage
    from repocache import server_root_control_host_preflight_v1 as host

    root, state, _, _, _ = filesystem

    def generation(number, previous=None):
        cfg = document(1, generation=number)
        cfg["deployment"]["paths"]["generated_include"] = native._OWNED_INCLUDE_PATH
        cfg["deployment"]["listen"]["bind_address"] = "127.0.0.1"
        active = fault == "active-route"
        cfg["repositories"][0]["desired_state"] = "active" if active else "disabled"
        raw = _canon(snapshot(generation=number, previous=previous, doc=cfg))
        main, include, catalog = native._render_owned_managed_candidate(
            cfg, number, "almalinux",
            {"repo-0": {"mirror0.example.invalid": ["8.8.8.8"]}} if active else {})
        return {V2_STATE: raw, native._OWNED_MAIN: main, native._INCLUDE: include,
                native._CATALOG: catalog, native._OWNED_MANIFEST:
                    native._owned_manifest_for(raw, main, include, catalog)}

    old = generation(1)
    new = generation(2, json.loads(old[V2_STATE]))
    withdrawn = {**old, native._CATALOG: None}
    initial = (old if fault.startswith("published-") else
               {**old, native._CATALOG: b"foreign initial catalog"}
               if fault == "initial-foreign-catalog" else withdrawn)
    paths = _owned_fixture_paths(filesystem, initial)
    catalog = paths[native._CATALOG]
    wal = native._owned_wal_record(old, new, live=True)
    pending = state / native._OWNED_WAL
    pending.write_bytes(wal if fault != "wrong-wal" else b"foreign WAL")
    pending.chmod(0o600)
    calls = []
    ns, exe = (17, 29), (31, 41)

    def auth():
        if fault in ("owner-drift", "published-owner-drift") and catalog.exists():
            raise native.NativeV2TransactionError("OWNER_CHANGED")

    def runtime(**kwargs):
        assert kwargs["namespace_identity"] == ns and kwargs["executable_identity"] == exe
        return {"main_pid_observed": 123}

    def policy(*args, **kwargs):
        assert not kwargs["allow_prepare"] and not kwargs["allow_boot_rollover"]
        kwargs["recheck_owned"]()
        return {"receipt": "different" if fault == "policy-drift" and catalog.exists() else "exact"}

    def health(root_fd, context, catalog_bytes, **kwargs):
        publish = kwargs["publish"]
        assert kwargs["require_withdrawn"] is not publish
        kwargs["recheck_owned"]()
        calls.append(publish)
        assert pending.read_bytes() == wal
        if fault == "foreign-catalog" and publish:
            catalog.write_bytes(b"foreign catalog")
            raise native.NativeV2TransactionError("FOREIGN_CATALOG")
        if fault == "wal-lost" and publish:
            pending.unlink()
            raise native.NativeV2TransactionError("WAL_LOST")
        if (fault == ("post-health" if publish else "pre-health")
                or (fault == "published-pre-health" and not publish)):
            raise native.NativeV2TransactionError("HEALTH_REFUSED")
        assert (catalog.read_bytes() if catalog.exists() else None) == catalog_bytes
        return {"main_pid": 123, "generation": 1, "catalog_observed": publish,
                "listener_inode": 5678 if publish and fault == "listener" else 1234}

    monkeypatch.setattr(host, "require_native_host_preconditions", lambda: None)
    monkeypatch.setattr(native, "_verify_current_root_fd", lambda *a: None)
    monkeypatch.setattr(native, "_require_audited_native_package_for_activation", lambda *a, **kw: None)
    monkeypatch.setattr(native, "_verify_tls_pair", lambda *a, **kw: "c"*64)
    monkeypatch.setattr(native, "_prepare_boot_egress_locked", policy)
    monkeypatch.setattr(native, "_owned_dedicated_live_health_bound", health)
    monkeypatch.setattr(unit, "_inspect_signed_owned_namespace_runtime", runtime)
    monkeypatch.setattr(storage, "prepare_dedicated_candidate_storage", lambda *a, **kw: {})
    monkeypatch.setattr(native, "_owned_alma_runtime_temps", lambda *a, **kw: ())
    monkeypatch.setattr(native, "verify_service_storage_mounts", lambda *a: None)
    monkeypatch.setattr(native, "_verify_owned_alma_runtime_service_view", lambda *a: None)
    monkeypatch.setattr(native.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=33))
    labels = {}
    if fault.startswith("published-") and fault != "published-bad-label":
        labels[catalog.stat().st_ino] = native._DEDICATED_PUBLIC_CONTEXT + b"\0"
    if fault == "published-wal-lost":
        pending.unlink()
    def label(fd, name):
        assert name == "security.selinux"
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            return native._DEDICATED_PUBLIC_CONTEXT + b"\0"
        return labels.get(os.fstat(fd).st_ino, b"unconfined_u:object_r:repocache_nginx_ro_t:s0\0")
    def set_label(fd, name, value):
        assert name == "security.selinux" and value == native._DEDICATED_PUBLIC_CONTEXT + b"\0"
        assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o600
        assert not catalog.exists()
        labels[os.fstat(fd).st_ino] = value
    monkeypatch.setattr(native.os, "listxattr", lambda fd: ["security.selinux"])
    monkeypatch.setattr(native.os, "getxattr", label)
    monkeypatch.setattr(native.os, "setxattr", set_label)

    def invoke():
        with native._locked(root, 0) as state_fd:
            return native._finish_owned_prepared_wal_dedicated_locked(
                root, state_fd, namespace_identity=ns, executable_identity=exe,
                expected_wal=wal, profile_receipt_sha256="a"*64,
                executable_receipt_sha256="b"*64, recheck_authenticated_owner=auth)

    if fault in ("none", "published-retry"):
        result = invoke()
        assert result["status"] == "OWNED_DEDICATED_WAL_ROLLBACK_OBSERVED"
        assert result["catalog_observed"] and not result["recovery_required"]
        assert result["wal_sha256"] == hashlib.sha256(wal).hexdigest()
        assert calls == [False, True]
        assert _fixture_resource_bytes(paths) == old
        _assert_owned_fixture_clean(filesystem, paths)
        with pytest.raises(native.NativeV2TransactionError):
            invoke()
        assert _fixture_resource_bytes(paths) == old
    else:
        with pytest.raises(native.NativeV2TransactionError):
            invoke()
        expected = ({**old, native._CATALOG: b"foreign catalog"} if fault == "foreign-catalog"
                    else initial if fault in ("initial-foreign-catalog", "published-bad-label",
                                             "published-owner-drift", "published-wal-lost")
                    else old if fault == "wal-lost" else withdrawn)
        assert _fixture_resource_bytes(paths) == expected
        if fault in ("wal-lost", "published-wal-lost"):
            assert not pending.exists()
        else:
            assert pending.read_bytes() == (b"foreign WAL" if fault == "wrong-wal" else wal)
        if fault in ("wrong-wal", "active-route", "initial-foreign-catalog",
                     "published-bad-label", "published-owner-drift", "published-wal-lost"):
            assert not calls
        assert not any((path.parent / native._OWNED_STAGES[name]).exists()
                       for name, path in paths.items())


@pytest.mark.parametrize("fault", ["stale", "timeout", "authority"])
def test_owned_live_generation_wait_uses_deadline_without_extending_authority_retry(monkeypatch, fault):
    identity = (123, (1, 2))
    clock = [0.0]
    calls = []
    monkeypatch.setattr(native.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(native.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(native, "_owned_live_observe", lambda fd: identity)
    def health(*args, **kwargs):
        calls.append(1)
        if fault == "stale" and len(calls) == 7:
            return
        native._deny("OWNED_LIVE_UNIT_CHANGED" if fault == "authority"
                     else "OWNED_LIVE_GENERATION_UNVERIFIED")
    monkeypatch.setattr(native, "_owned_live_health_bound", health)
    if fault == "stale":
        native._owned_live_wait_generation(0, identity, ({}, 2, "a" * 64))
        assert len(calls) == 7
    else:
        with pytest.raises(native.NativeV2TransactionError):
            native._owned_live_wait_generation(0, identity, ({}, 2, "a" * 64))
        assert len(calls) <= 61 and clock[0] <= 12
        if fault == "authority":
            assert len(calls) == 3
        else:
            assert clock[0] >= 11.9


@pytest.mark.parametrize("scenario", ["late", "rollback", "timeout", "wrong", "duplicate",
                                      "body", "encoding", "tls", "master-before", "master-after"])
def test_legacy_reload_generation_wait_is_bounded_and_exact(monkeypatch, scenario):
    expected, prior = (1, 2) if scenario == "rollback" else (2, 1)
    identity = ("a" * 64, 123)
    clock = [0.0]
    calls = []
    monkeypatch.setattr(native.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(native.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + delay))
    def observe(distribution):
        assert distribution == "debian"
        if scenario == "master-before" or (scenario == "master-after" and calls):
            return ("a" * 64, 124)
        return identity
    monkeypatch.setattr(native, "_native_reload_identity", observe)
    def request(doc, path, maximum):
        calls.append(1)
        assert path == native._HEALTH and maximum == 8192
        if scenario == "tls":
            native._deny("EXPOSURE_UNVERIFIED")
        value = (99 if scenario == "wrong" else expected if
                 scenario in ("duplicate", "body", "encoding", "master-after") or
                 (scenario in ("late", "rollback") and len(calls) >= 7) else prior)
        header = b"HTTP/1.1 204 No Content\r\nX-Repocache-Generation: " + str(value).encode()
        if scenario == "duplicate":
            header += b"\r\nX-Repocache-Generation: 2"
        if scenario == "encoding":
            header += b"\r\nContent-Encoding: gzip"
        return header + b"\r\n\r\n" + (b"unexpected" if scenario == "body" else b"")
    monkeypatch.setattr(native, "_fixed_https_get", request)
    if scenario in ("late", "rollback"):
        native._wait_native_generation({}, expected, "debian", identity, stale_generation=prior)
        assert len(calls) == 7
    else:
        with pytest.raises(native.NativeV2TransactionError):
            native._wait_native_generation({}, expected, "debian", identity, stale_generation=prior)
        if scenario == "timeout":
            assert 11.9 <= clock[0] <= 12 and len(calls) <= 61
        else:
            assert len(calls) == (0 if scenario == "master-before" else 1)
            assert clock[0] == 0


def test_legacy_compensation_audit_is_closed_and_redacted(capsys):
    for code in ("LEGACY_GENERATION_STALE", "APPLY_FAILED_ROLLED_BACK",
                 "APPLY_FAILED_RECOVERY_REQUIRED", "UNIT_CHANGED"):
        native._audit_native_failure(native.NativeV2TransactionError("NATIVE_V2_" + code))
    native._audit_native_failure(ValueError("private untrusted contents"))
    output = capsys.readouterr().err
    assert "private untrusted contents" not in output
    assert output.splitlines() == [
        "REPOCACHE_FIXED_TRANSACTION_REFUSAL: NATIVE_V2_" + code
        for code in ("LEGACY_GENERATION_STALE", "APPLY_FAILED_ROLLED_BACK",
                     "APPLY_FAILED_RECOVERY_REQUIRED", "UNIT_CHANGED", "OTHER_REFUSAL")]


@pytest.mark.parametrize("scenario", ["stopped", "active", "published", "foreign",
                                     "enabled", "vendor-active", "vendor-enabled",
                                     "failed-state", "changed-selection", "changed-master",
                                     "changed-unit", "bad-start", "finish-refusal",
                                     "stopped-published", "bad-wal", "owner-refusal"])
def test_composed_prepared_dedicated_recovery_selects_exact_service(monkeypatch, scenario):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from repocache import server_native_nginx_effective_unit_v1 as unit
    from repocache import server_root_control_host_preflight_v1 as host
    wal = b"exact WAL"
    old = {native._CATALOG: b"prior"}
    current = dict(old) if scenario in ("published", "stopped-published") else {native._CATALOG: None}
    if scenario == "foreign":
        current[native._CATALOG] = b"foreign"
    active = scenario in ("active", "published")
    calls = []
    observations = []
    @contextmanager
    def layout(root, state, *, recovering):
        assert (root, state, recovering) == (1, 2, True)
        yield state, 3, 4, lambda: None
    monkeypatch.setattr(host, "require_native_host_preconditions", lambda: None)
    monkeypatch.setattr(native, "_verify_current_root_fd", lambda *a: None)
    monkeypatch.setattr(native, "_require_audited_native_package_for_activation", lambda *a, **kw: None)
    monkeypatch.setattr(native, "_owned_layout_locked", layout)
    def require_wal(state, raw):
        assert (state, raw) == (2, wal)
        if scenario == "bad-wal":
            native._deny("OWNED_WAL_CHANGED")
    monkeypatch.setattr(native, "_owned_require_exact_wal", require_wal)
    monkeypatch.setattr(native, "_decode_owned_wal", lambda *a, **kw: (old, {}))
    monkeypatch.setattr(native, "_json", lambda *a, **kw: {"version": 3})
    snapshot = {"configuration_base64": "e30=", "state_generation": 1}
    monkeypatch.setattr(native, "_validate_owned_resources", lambda *a, **kw: snapshot)
    monkeypatch.setattr(native, "_owned_socket_require_inactive_routes", lambda *a: None)
    monkeypatch.setattr(native, "parse_install_bytes", lambda *a, **kw: {
        "deployment": {"listen": {"bind_address": "127.0.0.1", "https_port": 443}}})
    monkeypatch.setattr(native, "_read_owned_resources", lambda *a: current)
    monkeypatch.setattr(native, "_owned_live_guard", lambda *a: require_wal(2, a[-2]))
    monkeypatch.setattr(native, "_owned_check_stages_absent", lambda *a: None)
    monkeypatch.setattr(native, "_require_dedicated_public_label", lambda *a: None)
    monkeypatch.setattr(native, "_require_dedicated_catalog_label", lambda *a: None)
    monkeypatch.setattr(unit, "_safe_native_systemctl", lambda: None)
    def command(argv, **kw):
        assert argv[0] == native._SYSTEMCTL and kw["shell"] is False
        action, service = argv[1:]
        assert action in ("is-active", "is-enabled")
        if action == "is-enabled":
            enabled = ((scenario == "enabled" and service == native._OWNED_WAL_DOMAIN)
                       or (scenario == "vendor-enabled" and service == native._UNIT))
            return SimpleNamespace(returncode=0 if enabled else 1,
                                   stdout=b"enabled\n" if enabled else b"disabled\n")
        if service == native._UNIT:
            running = scenario == "vendor-active"
        else:
            observations.append(active)
            if scenario == "failed-state":
                return SimpleNamespace(returncode=3, stdout=b"failed\n")
            running = active or (scenario == "changed-selection" and len(observations) > 1)
        return SimpleNamespace(returncode=0 if running else 3,
                               stdout=b"active\n" if running else b"inactive\n")
    monkeypatch.setattr(native.subprocess, "run", command)
    def observe(*, https_port, active):
        assert https_port == 443
        return {"main_pid_observed": 123 if active else 0,
                "private_unit_identity": (5, 6), "private_dropin_identity": (7, 8)}
    monkeypatch.setattr(unit, "inspect_signed_owned_namespace_unit", observe)
    def runtime(**kw):
        assert active
        result = observe(https_port=kw["https_port"], active=True)
        if scenario == "changed-master":
            result["main_pid_observed"] = 124
        if scenario == "changed-unit":
            result["private_dropin_identity"] = (7, 9)
        return result
    monkeypatch.setattr(unit, "_inspect_signed_owned_namespace_runtime", runtime)
    def start(root, state, **kw):
        nonlocal active
        assert (root, state) == (1, 2) and not active
        assert kw["expected_stopped"] == observe(https_port=443, active=False)
        kw["recheck_authenticated_owner"]()
        calls.append("start")
        active = True
        return {"status": "OWNED_DEDICATED_PREPARED_WAL_START_OBSERVED",
                "wal_sha256": hashlib.sha256(wal).hexdigest(),
                "catalog_withdrawn": scenario != "bad-start", "recovery_required": True,
                "generation": 1, "enablement_changed": False, "main_pid": 123,
                "listener_inode": 567}
    monkeypatch.setattr(native, "_start_owned_prepared_wal_dedicated_locked", start)
    def finish(root, state, **kw):
        assert (root, state) == (1, 2) and active
        kw["recheck_authenticated_owner"]()
        assert kw["expected_runtime"] == observe(https_port=443, active=True)
        assert kw["expected_listener"] == (567 if "start" in calls else None)
        calls.append("finish")
        if scenario == "finish-refusal":
            native._deny("FINISH_REFUSED")
        return {"status": "OWNED_DEDICATED_WAL_ROLLBACK_OBSERVED"}
    monkeypatch.setattr(native, "_finish_owned_prepared_wal_dedicated_locked", finish)
    def auth():
        if scenario == "owner-refusal":
            native._deny("OWNER_REFUSED")
    def invoke():
        return native._recover_owned_prepared_dedicated_locked(
            1, 2, namespace_identity=(17, 29), executable_identity=(31, 41),
            profile_receipt_sha256="a"*64, executable_receipt_sha256="b"*64,
            expected_wal=wal, recheck_authenticated_owner=auth)
    if scenario in ("stopped", "active", "published"):
        assert invoke()["status"] == "OWNED_DEDICATED_WAL_ROLLBACK_OBSERVED"
        assert calls == (["start", "finish"] if scenario == "stopped" else ["finish"])
    else:
        with pytest.raises(native.NativeV2TransactionError):
            invoke()
        assert calls == (["start", "finish"] if scenario == "finish-refusal" else
                         ["start"] if scenario in ("changed-master", "changed-unit", "bad-start") else [])


def test_installed_dedicated_recovery_refuses_source_loader_before_host_access(monkeypatch):
    from repocache import server_root_control_host_preflight_v1 as host
    def forbidden():
        pytest.fail("source checkout must not authorize installed recovery")
    monkeypatch.setattr(host, "require_native_host_preconditions", forbidden)
    with pytest.raises(native.NativeV2TransactionError, match="INSTALLER_PIN_REFUSED"):
        native._recover_installed_prepared_dedicated({})
    with pytest.raises(native.NativeV2TransactionError, match="INSTALLER_PIN_REFUSED"):
        native._prepare_installed_committed_dedicated({})
    with pytest.raises(native.NativeV2TransactionError, match="INSTALLER_PIN_REFUSED"):
        native._start_installed_committed_dedicated({})
    with pytest.raises(native.NativeV2TransactionError, match="INSTALLER_PIN_REFUSED"):
        native._rollover_installed_committed_dedicated({})
    with pytest.raises(native.NativeV2TransactionError, match="INSTALLER_PIN_REFUSED"):
        native._rollover_installed_prepared_wal_dedicated({})
    with pytest.raises(native.NativeV2TransactionError, match="INSTALLER_PIN_REFUSED"):
        native._prepare_installed_prepared_wal_dedicated({})
    with pytest.raises(native.NativeV2TransactionError, match="INSTALLER_PIN_REFUSED"):
        native._resume_installed_prepared_wal_dedicated({})
    with pytest.raises(native.NativeV2TransactionError, match="INSTALLER_PIN_REFUSED"):
        native._resume_installed_committed_dedicated({})
    with pytest.raises(native.NativeV2TransactionError, match="INSTALLER_PIN_REFUSED"):
        native._start_installed_prepared_wal_dedicated({})


@pytest.mark.parametrize("fault", ["none", "lock-held", "placement", "worker-drift",
                                   "package", "vendor-drift", "wal", "executable",
                                   "profile", "boot", "boot-drift", "result",
                                   "prepare", "prepare-manifest", "prepare-service",
                                   "prepare-resource-drift", "prepare-result", "prepare-mixed",
                                   "start", "start-manifest", "start-boot", "start-service",
                                   "start-resource-drift", "start-result", "start-mixed",
                                   "rollover", "rollover-pin", "rollover-same-boot",
                                   "rollover-archive", "rollover-resource-drift",
                                   "pending-rollover", "pending-rollover-wal",
                                   "pending-rollover-catalog", "pending-rollover-drift",
                                   "pending-prepare", "pending-prepare-wal",
                                   "pending-prepare-catalog", "pending-prepare-drift",
                                   "pending-resume", "pending-resume-boot",
                                   "pending-resume-wal", "pending-resume-catalog",
                                   "pending-resume-drift", "pending-resume-result",
                                   "pending-start", "pending-start-wal", "pending-start-boot",
                                   "pending-start-catalog", "pending-start-drift", "pending-start-result",
                                   "committed-resume", "committed-resume-boot",
                                   "committed-resume-drift", "committed-resume-result"])
def test_installed_dedicated_recovery_rechecks_pins_under_real_lock(filesystem, monkeypatch, fault):
    """Actual protected files and flock; loader/host/package/runtime observations simulated."""
    import fcntl
    import zipimport
    from contextlib import contextmanager
    from types import SimpleNamespace
    from repocache import server_native_nginx_effective_unit_v1 as unit
    from repocache import server_native_nginx_executable_v1 as executable
    from repocache import server_native_egress_candidate_v1 as egress
    from repocache import server_root_control_host_preflight_v1 as host
    from repocache import server_root_control_worker_v1 as worker
    from repocache.server_protected_state_store_v1 import ProtectedStateStoreError, _canonical

    rootfd, state_path, _, _, _ = filesystem
    directory = state_path.parents[3] / "usr/libexec/repocache"
    directory.mkdir(parents=True, mode=0o755)
    wal = b"exact test WAL"
    pending_rolling = fault.startswith("pending-rollover")
    rolling = fault.startswith("rollover") or pending_rolling
    pending_first = fault.startswith("pending-prepare")
    committed_resume = fault.startswith("committed-resume")
    resuming = fault.startswith("pending-resume") or committed_resume
    pending_start = fault.startswith("pending-start")
    pending = pending_first or pending_rolling or (resuming and not committed_resume) or pending_start
    prior_boot_id = "11111111-1111-1111-1111-111111111111"
    new_boot_id = "22222222-2222-2222-2222-222222222222"
    boot = (_canonical({"boot_id": prior_boot_id}, limit=8192)
            if rolling else b"exact boot intent")
    placement = {
        "schema_version": 1, "status": "AUTHENTICATED_WORKER_STAGED", "version": "0.6.0",
        "source_sha": "a"*40, "archive_sha256": "b"*64, "manifest_sha256": "c"*64,
        "publisher_key_id": "test-only",
        "files": {name: "d"*64 for name in worker._RECEIPT_FILES},
        "authorizes_host_installation": False, "authorizes_service_activation": False,
    }
    raw = (json.dumps(placement, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    placement_sha = hashlib.sha256(raw).hexdigest()
    complete = worker._PLACEMENT_PREFIX + "complete-" + placement_sha
    for name, content in ((worker._RUNTIME_RECEIPT, b"foreign" if fault == "placement" else raw),
                          (complete, b""), (native._OWNED_WAL, wal),
                          (egress._BOOT_EGRESS_RECEIPT, boot)):
        path = state_path / name
        path.write_bytes(content)
        path.chmod(0o600)
    pins = dict(source_sha="a"*40, archive_sha256="b"*64, worker_sha256="d"*64,
                placement_sha256=placement_sha, package_identity="nginx-core-0:1.2-3.x86_64",
                native_payload_sha256="e"*64, binary_sha256="f"*64,
                executable_receipt_sha256="1"*64, profile_receipt_sha256="2"*64,
                boot_receipt_sha256=hashlib.sha256(boot).hexdigest(),
                wal_sha256="3"*64 if fault == "wal" else hashlib.sha256(wal).hexdigest())
    calls = []
    preparing = fault.startswith("prepare") or rolling or pending_first or resuming
    starting = fault.startswith("start") or pending_start
    manifest = b"exact committed manifest"
    resources = {native._OWNED_MANIFEST: manifest, native._CATALOG: b"catalog"}
    if preparing:
        if not pending:
            (state_path / native._OWNED_WAL).unlink()
        if not rolling and not resuming:
            (state_path / egress._BOOT_EGRESS_RECEIPT).unlink()
        pins["generation_manifest_sha256"] = ("0"*64 if fault == "prepare-manifest"
                                               else hashlib.sha256(manifest).hexdigest())
        if fault != "prepare-mixed":
            del pins["wal_sha256"], pins["boot_receipt_sha256"]
        if rolling:
            pins["previous_boot_receipt_sha256"] = ("0"*64 if fault == "rollover-pin"
                                                    else hashlib.sha256(boot).hexdigest())
            monkeypatch.setattr(egress, "_current_boot_id",
                                lambda: prior_boot_id if fault == "rollover-same-boot" else new_boot_id)
        if pending:
            pins["wal_sha256"] = ("0"*64 if fault.endswith("-wal")
                                  else hashlib.sha256(wal).hexdigest())
        if resuming:
            pins["boot_receipt_sha256"] = ("0"*64 if fault in ("pending-resume-boot", "committed-resume-boot")
                                            else hashlib.sha256(boot).hexdigest())
    if starting:
        if not pending_start:
            (state_path / native._OWNED_WAL).unlink()
        pins["generation_manifest_sha256"] = ("0"*64 if fault == "start-manifest"
                                               else hashlib.sha256(manifest).hexdigest())
        if pending_start:
            if fault == "pending-start-wal":
                pins["wal_sha256"] = "0"*64
        elif fault != "start-mixed":
            del pins["wal_sha256"]
        if fault in ("start-boot", "pending-start-boot"):
            pins["boot_receipt_sha256"] = "0"*64
    class Loader:
        archive = worker._WORKER
    monkeypatch.setattr(zipimport, "zipimporter", Loader)
    monkeypatch.setattr(native, "__loader__", Loader())
    monkeypatch.setattr(native, "sys", SimpleNamespace(flags=SimpleNamespace(isolated=True)))
    monkeypatch.setattr(host, "require_native_host_preconditions", lambda: None)
    monkeypatch.setattr(dispatcher, "_native_distro", lambda: "almalinux")
    monkeypatch.setattr(native, "_verify_current_root_fd", lambda *_: None)
    monkeypatch.setattr(native, "_require_audited_native_package_for_activation", lambda *a, **kw: None)
    real_locked, real_walk = native._locked, native._walk
    monkeypatch.setattr(native, "_locked", lambda root, uid: real_locked(rootfd, uid))
    monkeypatch.setattr(native, "_walk", lambda root, parts, stack, uid: real_walk(rootfd, parts, stack, uid))
    def digest(root, segments, mode, limit):
        if segments[-1] == "nginx":
            return "0"*64 if fault == "vendor-drift" else pins["binary_sha256"]
        return "0"*64 if fault == "worker-drift" else placement["files"][segments[-1]]
    monkeypatch.setattr(worker, "_placement_file_digest", digest)
    def rpm(argv, **kw):
        if argv[0] == native._SYSTEMCTL:
            assert (preparing or starting) and argv[2] in (native._UNIT, native._OWNED_WAL_DOMAIN)
            assert argv[1] in ("is-active", "is-enabled")
            if argv[1] == "is-active":
                active = fault in ("prepare-service", "start-service")
                return SimpleNamespace(returncode=0 if active else 3,
                                       stdout=b"active\n" if active else b"inactive\n")
            return SimpleNamespace(returncode=1, stdout=b"disabled\n")
        assert argv == ("/usr/bin/rpm", "-q",
                        "--queryformat=%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}",
                        "nginx-core")
        return SimpleNamespace(returncode=0, stderr=b"",
                               stdout=(b"wrong" if fault == "package" else pins["package_identity"].encode()))
    monkeypatch.setattr(native.subprocess, "run", rpm)
    monkeypatch.setattr(native, "_decode_owned_wal", lambda *a, **kw: ({}, {}))
    monkeypatch.setattr(native, "_validate_owned_resources", lambda *a, **kw: {
        "configuration_base64": "e30=", "state_generation": 1})
    monkeypatch.setattr(native, "_owned_socket_require_inactive_routes", lambda *a: None)
    monkeypatch.setattr(native, "parse_install_bytes", lambda *a, **kw: {
        "deployment": {"listen": {"https_port": 443, "bind_address": "127.0.0.1"}}})
    monkeypatch.setattr(unit, "_signed_owned_unit_bytes", lambda: b"signed unit")
    if preparing or starting:
        @contextmanager
        def layout(root, state, *, recovering):
            assert recovering is pending
            yield state, 11, 12, lambda: None
        monkeypatch.setattr(native, "_owned_layout_locked", layout)
        if pending:
            prior_resources = dict(resources)
            monkeypatch.setattr(native, "_decode_owned_wal", lambda *a, **kw: (prior_resources, {}))
            resources[native._CATALOG] = b"foreign" if fault.endswith("-catalog") else None
            def live_guard(state, nginx, public, check, expected_wal, expected_resources):
                check()
                if ((state_path / native._OWNED_WAL).read_bytes() != expected_wal
                        or resources != expected_resources):
                    native._deny("OWNED_LIVE_RESOURCE_DRIFT")
            monkeypatch.setattr(native, "_owned_live_guard", live_guard)
            monkeypatch.setattr(native, "_owned_check_stages_absent", lambda *a: None)
        monkeypatch.setattr(native, "_read_owned_resources", lambda *a: dict(resources))
        monkeypatch.setattr(unit, "_safe_native_systemctl", lambda: None)
        monkeypatch.setattr(unit, "inspect_signed_owned_namespace_unit", lambda **kw: {
            "main_pid_observed": 0})
        monkeypatch.setattr(native.pwd, "getpwnam", lambda *_: SimpleNamespace(pw_uid=987))
    monkeypatch.setattr(executable, "signed_owned_nginx_policy_candidate",
                        lambda: {"policy_sha256": "4"*64})
    def verify(directory_fd, **kw):
        assert kw["expected_receipt_sha256"] == pins["executable_receipt_sha256"]
        assert kw["native_payload_sha256"] == pins["native_payload_sha256"]
        assert kw["authenticated_sha256"] == pins["binary_sha256"]
        assert kw["dedicated_policy_sha256"] == "4"*64
        if fault == "executable":
            native._deny("EXECUTABLE_REFUSED")
        return {"executable_identity": (17, 29)}
    monkeypatch.setattr(executable, "verify_nginx_candidate_receipt", verify)
    def profile(*a, **kw):
        assert kw["allow_create"] is False
        return {"receipt_sha256": "0"*64 if fault == "profile" else pins["profile_receipt_sha256"]}
    monkeypatch.setattr(unit, "_stage_namespace_dropin_under_lock", profile)
    @contextmanager
    def namespace():
        yield 11, (31, 41), lambda: None
    monkeypatch.setattr(egress, "_fixed_namespace_scope", namespace)
    if fault == "boot":
        pins["boot_receipt_sha256"] = "0"*64
    def recover(root, state, **kw):
        calls.append("recover")
        # A separate open file description must be excluded even in this
        # process; a directory descriptor alone cannot establish this.
        contender = os.open(state_path / LOCK_NAME, os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(contender)
        assert kw["expected_wal"] == wal and kw["namespace_identity"] == (31, 41)
        assert kw["executable_identity"] == (17, 29)
        kw["recheck_authenticated_owner"]()
        if fault == "boot-drift":
            (state_path / egress._BOOT_EGRESS_RECEIPT).write_bytes(b"changed")
            kw["recheck_authenticated_owner"]()
        if fault != "result":
            os.unlink(native._OWNED_WAL, dir_fd=state)
        return {"status": "OWNED_DEDICATED_WAL_ROLLBACK_OBSERVED",
                "wal_sha256": pins["wal_sha256"], "recovery_required": False,
                "catalog_observed": True}
    monkeypatch.setattr(native, "_recover_owned_prepared_dedicated_locked", recover)
    if preparing:
        def create(root, state, **kw):
            calls.append("prepare")
            contender = os.open(state_path / LOCK_NAME, os.O_RDONLY)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(contender)
            assert kw["allow_boot_rollover"] is rolling
            if rolling:
                assert kw["expected_previous_receipt_sha256"] == hashlib.sha256(boot).hexdigest()
            if pending:
                assert kw["expected_wal"] == wal
            kw["recheck_stopped_owner"]()
            if fault in ("prepare-resource-drift", "rollover-resource-drift", "pending-rollover-drift", "pending-prepare-drift"):
                resources[native._CATALOG] = b"changed"
                kw["recheck_stopped_owner"]()
            if rolling and fault != "rollover-archive":
                archive = state_path / (egress._BOOT_EGRESS_HISTORY_PREFIX + prior_boot_id)
                archive.write_bytes(boot)
                archive.chmod(0o600)
            if rolling:
                (state_path / egress._BOOT_EGRESS_RECEIPT).write_bytes(b"new boot intent")
            return {"namespace_device": 31, "namespace_inode": 41,
                    "generation_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                    **({"boot_id": new_boot_id, "receipt_sha256": hashlib.sha256(b"new boot intent").hexdigest()}
                       if rolling else {})}

        def resume(root, state, **kw):
            calls.append("resume")
            contender = os.open(state_path / LOCK_NAME, os.O_RDONLY)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(contender)
            assert kw["expected_wal"] == wal and kw["namespace_identity"] == (31, 41)
            kw["recheck_stopped_owner"]()
            if fault == "pending-resume-drift":
                (state_path / egress._BOOT_EGRESS_RECEIPT).write_bytes(b"foreign")
                kw["recheck_stopped_owner"]()
            return {"namespace_device": 31, "namespace_inode": 41,
                    "generation_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                    "receipt_sha256": "0"*64 if fault == "pending-resume-result"
                    else hashlib.sha256(boot).hexdigest()}

        def verify_boot(root, state, **kw):
            if committed_resume and kw["allow_prepare"]:
                calls.append("resume")
                assert kw["expected_existing_receipt"] == boot
                assert kw["namespace_identity"] == (31, 41)
                contender = os.open(state_path / LOCK_NAME, os.O_RDONLY)
                try:
                    with pytest.raises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(contender)
                kw["recheck_namespace_owner"]()
                if fault == "committed-resume-drift":
                    (state_path / egress._BOOT_EGRESS_RECEIPT).write_bytes(b"foreign")
                    kw["recheck_namespace_owner"]()
                return {"namespace_device": 31, "namespace_inode": 41,
                        "generation_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                        "receipt_sha256": "0"*64 if fault == "committed-resume-result"
                        else hashlib.sha256(boot).hexdigest()}
            calls.append("verify")
            assert kw["namespace_identity"] == (31, 41)
            if pending:
                assert kw["expected_wal"] == wal
                kw["recheck_stopped_owner"]()
            else:
                assert kw["allow_prepare"] is False
                kw["recheck_namespace_owner"]()
            return {"namespace_device": 31, "namespace_inode": 41,
                    "generation_manifest_sha256": "0"*64 if fault == "prepare-result"
                    else hashlib.sha256(manifest).hexdigest(),
                    **({"boot_id": new_boot_id, "receipt_sha256": hashlib.sha256(b"new boot intent").hexdigest()}
                       if rolling else {"receipt_sha256": hashlib.sha256(boot).hexdigest()} if resuming else {})}

        monkeypatch.setattr(native, "_resume_owned_prepared_wal_boot_egress_locked", resume)
        monkeypatch.setattr(native, "_create_owned_committed_boot_egress_locked", create)
        monkeypatch.setattr(native, "_prepare_owned_committed_boot_egress_locked", verify_boot)
        monkeypatch.setattr(native, "_create_owned_prepared_wal_boot_egress_locked", create)
        monkeypatch.setattr(native, "_verify_owned_prepared_wal_boot_egress_locked", verify_boot)
        invoke = (native._resume_installed_committed_dedicated if committed_resume
                  else native._resume_installed_prepared_wal_dedicated if resuming
                  else native._rollover_installed_prepared_wal_dedicated if pending_rolling
                  else native._prepare_installed_prepared_wal_dedicated if pending_first
                  else native._rollover_installed_committed_dedicated if rolling
                  else native._prepare_installed_committed_dedicated)
        if fault in ("prepare", "rollover", "pending-rollover", "pending-prepare", "pending-resume",
                     "committed-resume"):
            assert invoke(pins)["namespace_inode"] == 41
        else:
            with pytest.raises(native.NativeV2TransactionError):
                invoke(pins)
        assert calls == (["resume", "verify"] if fault in ("pending-resume", "pending-resume-result",
                                                           "committed-resume", "committed-resume-result") else
                         ["resume"] if fault in ("pending-resume-drift", "committed-resume-drift") else
                         ["prepare", "verify"] if fault in (
                             "prepare", "prepare-result", "rollover", "rollover-archive",
                             "pending-rollover", "pending-prepare") else
                         ["prepare"] if fault in ("prepare-resource-drift", "rollover-resource-drift",
                                                  "pending-rollover-drift", "pending-prepare-drift") else [])
        if rolling and fault in ("rollover-pin", "rollover-same-boot", "rollover-resource-drift",
                                 "pending-rollover-wal", "pending-rollover-catalog", "pending-rollover-drift"):
            assert (state_path / egress._BOOT_EGRESS_RECEIPT).read_bytes() == boot
            assert not list(state_path.glob(egress._BOOT_EGRESS_HISTORY_PREFIX + "*"))
        if resuming and not fault.endswith("-drift"):
            assert (state_path / egress._BOOT_EGRESS_RECEIPT).read_bytes() == boot
        if pending_first and fault != "pending-prepare":
            assert not (state_path / egress._BOOT_EGRESS_RECEIPT).exists()
            assert not list(state_path.glob(egress._BOOT_EGRESS_HISTORY_PREFIX + "*"))
        if pending:
            assert (state_path / native._OWNED_WAL).read_bytes() == wal
        else:
            assert not (state_path / native._OWNED_WAL).exists()
        return
    if starting:
        def start(root, state, **kw):
            calls.append("start")
            contender = os.open(state_path / LOCK_NAME, os.O_RDONLY)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(contender)
            assert kw["namespace_identity"] == (31, 41)
            assert kw["executable_identity"] == (17, 29)
            kw["recheck_authenticated_owner"]()
            if pending_start:
                assert kw["expected_wal"] == wal
            else:
                assert "expected_wal" not in kw
            if fault in ("start-resource-drift", "pending-start-drift"):
                resources[native._CATALOG] = b"changed"
                kw["recheck_authenticated_owner"]()
            result = {"status": "OWNED_DEDICATED_COMMITTED_START_OBSERVED",
                      "generation": 1, "catalog_observed": True,
                      "service_storage_mounts_verified": True,
                      "service_scratch_mounts_verified": True,
                      "enablement_changed": fault == "start-result"}
            if pending_start:
                result.update(status="OWNED_DEDICATED_PREPARED_WAL_START_OBSERVED",
                              catalog_observed=fault == "pending-start-result",
                              catalog_withdrawn=True, recovery_required=True,
                              wal_sha256=hashlib.sha256(wal).hexdigest())
            return result
        monkeypatch.setattr(native, "_start_owned_committed_dedicated_locked", start)
        monkeypatch.setattr(native, "_start_owned_prepared_wal_dedicated_locked", start)
        invoke = (native._start_installed_prepared_wal_dedicated if pending_start
                  else native._start_installed_committed_dedicated)
        if fault in ("start", "pending-start"):
            assert invoke(pins)["catalog_observed"] is (not pending_start)
        else:
            with pytest.raises(native.NativeV2TransactionError):
                invoke(pins)
        assert calls == (["start"] if fault in ("start", "start-resource-drift", "start-result",
                                                "pending-start", "pending-start-drift", "pending-start-result") else [])
        if pending_start:
            assert (state_path / native._OWNED_WAL).read_bytes() == wal
        else:
            assert not (state_path / native._OWNED_WAL).exists()
        assert (state_path / egress._BOOT_EGRESS_RECEIPT).read_bytes() == boot
        return
    if fault == "none":
        assert native._recover_installed_prepared_dedicated(pins)["catalog_observed"]
        assert not (state_path / native._OWNED_WAL).exists()
    elif fault == "lock-held":
        with real_locked(rootfd, 0):
            with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
                native._recover_installed_prepared_dedicated(pins)
    else:
        with pytest.raises(native.NativeV2TransactionError):
            native._recover_installed_prepared_dedicated(pins)
    assert calls == (["recover"] if fault in ("none", "boot-drift", "result") else [])
    if fault != "none":
        assert (state_path / native._OWNED_WAL).read_bytes() == wal
    # Whether successful or refused, the worker must release its lock.
    with real_locked(rootfd, 0):
        pass

@pytest.mark.parametrize("previous, pin", [(None, "a"*64), (b"old", "a"*64)])
def test_committed_rollover_pin_refusal_precedes_namespace_effect(monkeypatch, previous, pin):
    calls = []
    monkeypatch.setattr(native, "_fresh_boot_egress_intent_locked",
                        lambda *a, **kw: ("new-boot", previous))
    def create(**kw):
        pytest.fail("mismatched prior boot reached namespace creation")
    monkeypatch.setattr(native, "_create_fixed_loopback_namespace_locked", create)
    plan = {"destinations": [], "nft_candidate": "test", "generation": 1,
            "generation_manifest_sha256": "a"*64}
    with pytest.raises(native.NativeV2TransactionError, match="INTENT_CHANGED"):
        native._create_owned_boot_egress_from_plan_locked(
            1, 2, plan, lambda: calls.append("state"),
            profile_receipt_sha256="b"*64, executable_receipt_sha256="c"*64,
            recheck_stopped_owner=lambda: calls.append("owner"),
            allow_boot_rollover=True, expected_previous_receipt_sha256=pin)
    assert calls == ["state", "owner", "state"]


@pytest.mark.parametrize("fault", ["none", "missing-history", "foreign-history", "wrong-current",
                                    "wal", "orphan", "rules", "drift", "history-drift"])
def test_retained_rolled_committed_selection_reconstructs_from_real_protected_bytes(
        filesystem, monkeypatch, fault):
    """Real retained resources and history; only kernel namespace IO simulated."""
    from contextlib import contextmanager
    from types import SimpleNamespace
    from repocache import server_native_egress_candidate_v1 as egress
    from repocache.server_protected_state_store_v1 import _canonical

    rootfd, state, _, _, events = filesystem
    cfg = document(1, generation=1)
    cfg["deployment"]["paths"]["generated_include"] = native._OWNED_INCLUDE_PATH
    cfg["deployment"]["listen"]["bind_address"] = "127.0.0.1"
    cfg["repositories"][0]["desired_state"] = "disabled"
    raw = _canon(snapshot(generation=1, previous=None, doc=cfg))
    main, include, catalog = native._render_owned_managed_candidate(cfg, 1, "almalinux", {})
    resources = {V2_STATE: raw, native._OWNED_MAIN: main, native._INCLUDE: include,
                 native._CATALOG: catalog,
                 native._OWNED_MANIFEST: native._owned_manifest_for(raw, main, include, catalog)}
    paths = _owned_fixture_paths(filesystem, resources)
    plan = native._owned_boot_egress_plan(resources, distribution="almalinux", worker_uid=987)
    old_boot = "11111111-1111-1111-1111-111111111111"
    current_boot = "22222222-2222-2222-2222-222222222222"
    old_record = dict(schema_version=1, boot_id=old_boot, namespace_device=1,
                      namespace_inode=2, generation=plan["generation"],
                      generation_manifest_sha256=plan["generation_manifest_sha256"],
                      profile_receipt_sha256="a"*64, executable_receipt_sha256="b"*64,
                      ruleset_sha256=hashlib.sha256(egress._canonical_ruleset(
                          plan["nft_candidate"]).encode("ascii")).hexdigest(),
                      authorizes_nginx_activation=False)
    now_record = dict(old_record, boot_id=current_boot, namespace_device=7, namespace_inode=8)
    history_path = state / (egress._BOOT_EGRESS_HISTORY_PREFIX + old_boot)
    receipt_path = state / egress._BOOT_EGRESS_RECEIPT
    if fault == "foreign-history":
        old_record["executable_receipt_sha256"] = "0"*64
    if fault == "wrong-current":
        now_record["namespace_inode"] = 9

    def place(path, data):
        path.write_bytes(data)
        path.chmod(0o600)

    if fault != "missing-history":
        place(history_path, _canonical(old_record, limit=4096))
    place(receipt_path, _canonical(now_record, limit=4096))
    if fault == "wal":
        place(state / native._OWNED_WAL, b"untrusted")
    if fault == "orphan":
        place(state / native._OWNED_WAL_TMP, b"untrusted")
    before = {p.name: p.read_bytes() for p in state.iterdir()}
    monkeypatch.setattr(native, "_verify_current_root_fd", lambda fd: None)
    monkeypatch.setattr(native.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=987))
    monkeypatch.setattr(egress, "_current_boot_id", lambda: current_boot)

    @contextmanager
    def namespace():
        yield 17, (7, 8), lambda: None
    monkeypatch.setattr(egress, "_fixed_namespace_scope", namespace)
    observed = []
    def rules(fd):
        assert fd == 17
        observed.append(fd)
        if fault == "drift":
            paths[native._OWNED_MAIN].write_bytes(b"foreign")
        elif fault == "history-drift":
            place(history_path, b"foreign")
        return "" if fault == "rules" else plan["nft_candidate"]
    monkeypatch.setattr(egress, "_read_namespace_rules", rules)
    with native._locked(rootfd, 0) as statefd:
        def invoke():
            return native._retained_rolled_committed_dedicated_pins_locked(rootfd, statefd)
        if fault == "none":
            assert invoke() == {
                "profile_receipt_sha256": "a"*64, "executable_receipt_sha256": "b"*64,
                "boot_receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                "generation_manifest_sha256": plan["generation_manifest_sha256"]}
            assert observed == [17, 17]
        else:
            with pytest.raises((native.NativeV2TransactionError, egress.NativeEgressCandidateError)):
                invoke()
    assert not events
    if fault != "drift":
        assert _fixture_resource_bytes(paths) == resources
    if fault != "history-drift":
        assert {p.name: p.read_bytes() for p in state.iterdir()} == before
