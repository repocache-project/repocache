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
    assert not events
    second = _canon(snapshot(count=1, generation=2, previous=first))
    assert installer._stage_proposal_under_root(
        fd, second, hashlib.sha256(second).hexdigest(),
    )["expected_generation"] == 1
    assert (state / V2_STATE).read_bytes() == raw


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
    assert not events


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
