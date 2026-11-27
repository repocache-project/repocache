"""Pure candidate egress: exact canonical render, no privileged effects."""
from __future__ import annotations

import hashlib
import pytest

from repocache.server_native_egress_candidate_v1 import (
    NativeEgressCandidateError, derive_pinned_egress_candidate,
    render_namespace_egress_candidate,
)
from repocache.server_nginx_repository_bundle_v1 import render_repository_nginx_bundle_candidate
from test_server_proposed_state_v2_store import document


def fixture(*, both=True):
    doc = document(count=2, generation=1)
    doc["repositories"][0]["desired_state"] = "active"
    doc["repositories"][1]["desired_state"] = "active" if both else "disabled"
    doc["repositories"][0]["upstream"]["allowed_hosts"].append("alternate.example.invalid")
    doc["repositories"][1]["upstream"]["base_url"] = (
        "https://mirror1.example.invalid:8008/repo/"
    )
    pins = {"repo-0": {"mirror0.example.invalid": ["2001:4860:4860::8888", "8.8.8.8"],
                       "alternate.example.invalid": ["9.9.9.9"]}}
    if both:
        pins["repo-1"] = {"mirror1.example.invalid": ["1.1.1.1"]}
    fragment = render_repository_nginx_bundle_candidate(
        doc, expected_state_generation=1, candidate_pins_by_repository=pins,
        ca_bundle_path="/etc/ssl/certs/ca-certificates.crt",
    )["http_upstream_fragment"].encode("ascii")
    return doc, fragment


def test_exact_tuple_candidate_and_disabled_withdrawal():
    doc, raw = fixture()
    plan = render_namespace_egress_candidate(doc, generation=1, http_fragment=raw, worker_uid=987)
    assert plan["http_sha256"] == hashlib.sha256(raw).hexdigest()
    assert plan["destinations"] == (("1.1.1.1", 8008), ("8.8.8.8", 443),
                                    ("2001:4860:4860::8888", 443))
    rules = plan["nft_candidate"]
    assert "policy drop;" in rules and "ct state related" not in rules
    assert "meta skuid 987 ip daddr 1.1.1.1 tcp dport 8008 ct state new accept" in rules
    assert "meta skuid 987 ip6 daddr 2001:4860:4860::8888 tcp dport 443" in rules
    assert "meta skuid 987 ip daddr 1.1.1.1 tcp dport 443" not in rules
    assert "meta skuid 987 ip daddr 8.8.8.8 tcp dport 8008" not in rules
    assert "9.9.9.9" not in rules
    assert 'meta skuid 0 oifname "lo"' in rules
    assert not plan["authorizes_firewall_change"] and not plan["runtime_egress_verified"]
    doc, raw = fixture(both=False)
    next_plan = render_namespace_egress_candidate(
        doc, generation=1, http_fragment=raw, worker_uid=987)
    assert "1.1.1.1" not in next_plan["nft_candidate"]


@pytest.mark.parametrize("fault", [
    "wrong-port", "private", "duplicate", "extra-directive", "missing",
    "foreign-group", "wrong-family", "noncanonical", "extra-group", "stale",
])
def test_refuse_noncanonical_or_unapproved_egress(fault):
    doc, raw = fixture()
    generation = 1
    if fault == "wrong-port":
        raw = raw.replace(b"8.8.8.8:443;", b"8.8.8.8:8008;")
    elif fault == "private":
        raw = raw.replace(b"8.8.8.8:443;", b"127.0.0.1:443;")
    elif fault == "duplicate":
        raw = raw.replace(b"    server 8.8.8.8:443;\n",
                          b"    server 8.8.8.8:443;\n    server 8.8.8.8:443;\n")
    elif fault == "extra-directive":
        raw += b"resolver 8.8.8.8;\n"
    elif fault == "missing":
        raw = b""
    elif fault == "foreign-group":
        raw = raw.replace(b"repocache_pin_repo_0", b"repocache_pin_foreign")
    elif fault == "wrong-family":
        raw = raw.replace(b"8.8.8.8:443;", b"[8.8.8.8]:443;")
    elif fault == "noncanonical":
        raw = raw.replace(b":443;", b":00443;")
    elif fault == "extra-group":
        raw += raw
    else:
        generation = 2
    with pytest.raises(NativeEgressCandidateError, match="NATIVE_EGRESS_CANDIDATE_INVALID"):
        derive_pinned_egress_candidate(doc, generation=generation, http_fragment=raw)


@pytest.mark.parametrize("uid", [0, -1, 2**31, True, "987"])
def test_invalid_worker_identity(uid):
    doc, raw = fixture()
    with pytest.raises(NativeEgressCandidateError, match="NATIVE_EGRESS_WORKER_UID_INVALID"):
        render_namespace_egress_candidate(doc, generation=1, http_fragment=raw, worker_uid=uid)


def test_inactive_generation_has_no_worker_connections():
    doc = document(count=1, generation=1)
    doc["repositories"][0]["desired_state"] = "disabled"
    plan = render_namespace_egress_candidate(doc, generation=1, http_fragment=b"", worker_uid=987)
    assert plan["destinations"] == ()
    assert "meta skuid 987" not in plan["nft_candidate"]


def test_closed_namespace_readback_accepts_only_format_equivalence():
    from repocache.server_native_egress_candidate_v1 import verify_namespace_egress_readback
    doc, raw = fixture()
    expected = render_namespace_egress_candidate(
        doc, generation=1, http_fragment=raw, worker_uid=987)["nft_candidate"]
    observed = expected.replace("priority 0", "priority filter").replace(
        "meta l4proto tcp", "meta l4proto 6").replace(
        "counter name denied", 'counter name "denied"').replace(
        "counter denied { }", "counter denied {\n\t}")
    report = verify_namespace_egress_readback(expected, observed)
    assert report["ruleset_shape_matches"]
    assert not report["runtime_egress_verified"] and not report["authorizes_firewall_change"]


@pytest.mark.parametrize("fault", [
    "foreign-table", "accept-default", "wrong-uid", "wrong-port",
    "missing-rule", "extra-rule", "related", "reordered", "wrong-health",
    "duplicate", "extra-verdict", "foreign-counter",
])
def test_closed_namespace_readback_refuses_policy_drift(fault):
    from repocache.server_native_egress_candidate_v1 import verify_namespace_egress_readback
    doc, raw = fixture()
    expected = render_namespace_egress_candidate(
        doc, generation=1, http_fragment=raw, worker_uid=987)["nft_candidate"]
    line = "        meta skuid 987 ip daddr 1.1.1.1 tcp dport 8008 ct state new accept\n"
    if fault == "foreign-table":
        observed = expected + "table ip foreign { }\n"
    elif fault == "accept-default":
        observed = expected.replace("policy drop", "policy accept")
    elif fault == "wrong-uid":
        observed = expected.replace("skuid 987", "skuid 988")
    elif fault == "wrong-port":
        observed = expected.replace("dport 8008", "dport 443")
    elif fault == "missing-rule":
        observed = expected.replace(line, "")
    elif fault == "extra-rule":
        observed = expected.replace(line, line + line.replace("1.1.1.1", "9.9.9.9"))
    elif fault == "related":
        observed = expected.replace("state established", "state established,related")
    elif fault == "reordered":
        other = "        meta skuid 987 ip daddr 8.8.8.8 tcp dport 443 ct state new accept\n"
        observed = expected.replace(line + other, other + line)
    elif fault == "wrong-health":
        observed = expected.replace('oifname "lo"', 'oifname "eth0"')
    elif fault == "duplicate":
        observed = expected.replace(line, line + line)
    elif fault == "extra-verdict":
        observed = expected.replace("counter name denied reject", "accept\n        counter name denied reject")
    else:
        observed = expected.replace("counter name denied", "counter name other")
    assert observed != expected
    with pytest.raises(NativeEgressCandidateError, match="NATIVE_EGRESS_READBACK_REFUSED"):
        verify_namespace_egress_readback(expected, observed)


@pytest.mark.parametrize("fault", ["none", "rename", "parent", "drift", "program"])
def test_fixed_namespace_readback_rechecks_retained_descriptors(tmp_path, monkeypatch, fault):
    import os
    from repocache import server_native_egress_candidate_v1 as egress
    from repocache import server_root_control_host_preflight_v1 as host

    # Synthetic descriptor fixture only: kernel type, native credentials
    # and actual nft execution are separately exercised in the booted VM.
    root = tmp_path / "root"
    parent = root / "run" / "netns"
    parent.mkdir(parents=True)
    named = parent / "repocache-nginx"
    named.write_bytes(b"fixture")
    expected = egress.render_bootstrap_egress_candidate(worker_uid=987)["nft_candidate"]
    real_open = os.open

    def open_root(path, flags, *args, **kwargs):
        return real_open(root if path == "/" else path, flags, *args, **kwargs)

    def identity(st):
        return st.st_dev, st.st_ino

    def directory(fd):
        st = os.fstat(fd)
        return st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid

    monkeypatch.setattr(os, "open", open_root)
    monkeypatch.setattr(host, "require_native_host_preconditions", lambda: None)
    monkeypatch.setattr(egress, "_namespace_parent_identity", directory)
    monkeypatch.setattr(egress, "_namespace_identity", identity)
    monkeypatch.setattr(egress, "_verify_network_namespace_fd",
                        lambda fd: identity(os.fstat(fd)))
    programs = [1]
    monkeypatch.setattr(egress, "_safe_readback_programs", lambda: tuple(programs))
    read_fds = []
    original = identity(named.stat())

    def read(fd):
        assert identity(os.fstat(fd)) == original
        read_fds.append(fd)
        if len(read_fds) == 1:
            if fault == "rename":
                named.rename(parent / "retained")
                named.write_bytes(b"foreign")
            elif fault == "parent":
                parent.rename(root / "run" / "retained")
                parent.mkdir()
                named.write_bytes(b"foreign")
            elif fault == "program":
                programs.append(2)
        if fault == "drift" and len(read_fds) == 2:
            return expected.replace("policy drop", "policy accept")
        return expected

    monkeypatch.setattr(egress, "_read_namespace_rules", read)
    if fault == "none":
        report = egress.inspect_fixed_namespace_egress(expected)
        assert len(read_fds) == 2 and read_fds[0] == read_fds[1]
        assert (report["namespace_device"], report["namespace_inode"]) == original
        assert report["fixed_namespace_identity_observed"]
        assert not report["namespace_exclusivity_verified"]
        assert not report["runtime_egress_verified"]
        assert not report["authorizes_firewall_change"]
    else:
        with pytest.raises(NativeEgressCandidateError):
            egress.inspect_fixed_namespace_egress(expected)
        assert len(read_fds) == (2 if fault == "drift" else 1)
    with pytest.raises(OSError):
        os.fstat(read_fds[0])


def test_fixed_namespace_rejects_invalid_expected_before_host_probe(monkeypatch):
    from repocache import server_native_egress_candidate_v1 as egress
    from repocache import server_root_control_host_preflight_v1 as host

    def unexpected():
        pytest.fail("invalid candidate reached native preflight")

    monkeypatch.setattr(host, "require_native_host_preconditions", unexpected)
    with pytest.raises(NativeEgressCandidateError, match="NAMESPACE_READBACK_REFUSED"):
        egress.inspect_fixed_namespace_egress("table ip foreign {}")


@pytest.mark.parametrize("fault", ["host", "type", "owner", "none"])
def test_namespace_kernel_ioctl_type_owner_and_host_checks(monkeypatch, fault):
    import fcntl
    import os
    import stat
    from types import SimpleNamespace
    from repocache import server_native_egress_candidate_v1 as egress

    def info(ino):
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o444, st_uid=0,
                               st_gid=0, st_dev=3, st_ino=ino)

    calls = []
    closed = []
    namespace_fd, owner_fd = 1000000, 1000001
    real_ioctl, real_fstat, real_stat, real_close = (
        fcntl.ioctl, os.fstat, os.stat, os.close)
    paths = {"/proc/1/ns/user": 40, "/proc/1/ns/net": 20,
             "/proc/self/ns/net": 21}

    def ioctl(fd, op, *args, **kwargs):
        if fd != namespace_fd:
            return real_ioctl(fd, op, *args, **kwargs)
        calls.append((fd, op))
        if op == egress._NS_GET_NSTYPE:
            return 0x20000 if fault == "type" else egress._CLONE_NEWNET
        assert op == egress._NS_GET_USERNS
        return owner_fd

    def fstat(fd):
        if fd == namespace_fd:
            return info(20 if fault == "host" else 30)
        if fd == owner_fd:
            return info(41 if fault == "owner" else 40)
        return real_fstat(fd)

    def stat_path(path, *args, **kwargs):
        if isinstance(path, str) and path in paths and not args and not kwargs:
            return info(paths[path])
        return real_stat(path, *args, **kwargs)

    def close(fd):
        if fd == owner_fd:
            closed.append(fd)
        else:
            real_close(fd)

    # Do not intercept pytest capture or unrelated runtime descriptors.
    with monkeypatch.context() as scoped:
        scoped.setattr(fcntl, "ioctl", ioctl)
        scoped.setattr(os, "fstat", fstat)
        scoped.setattr(os, "stat", stat_path)
        scoped.setattr(os, "close", close)
        if fault == "none":
            assert egress._verify_network_namespace_fd(namespace_fd) == (3, 30)
        else:
            with pytest.raises(NativeEgressCandidateError, match={
                "host": "HOST_NAMESPACE_REFUSED", "type": "NAMESPACE_TYPE_REFUSED",
                "owner": "NAMESPACE_OWNER_REFUSED",
            }[fault]):
                egress._verify_network_namespace_fd(namespace_fd)
    assert calls == ([(namespace_fd, egress._NS_GET_NSTYPE)] +
                     ([] if fault == "type" else
                      [(namespace_fd, egress._NS_GET_USERNS)]))
    assert closed == ([] if fault == "type" else [owner_fd])


@pytest.mark.parametrize("fault", ["none", "large", "nonzero"])
def test_namespace_listing_is_fixed_bounded_and_read_only(monkeypatch, fault):
    import os
    import subprocess
    import sys
    from repocache import server_native_egress_candidate_v1 as egress

    real_popen = subprocess.Popen
    fd = os.open("/dev/null", os.O_RDONLY)
    payload = ("import sys; sys.stdout.write('x' * 1048577)" if fault == "large"
               else "raise SystemExit(1)" if fault == "nonzero" else "print('fixed')")
    calls = []

    def popen(argv, **kwargs):
        calls.append(argv)
        assert argv == ("/usr/bin/nsenter", "--net=/proc/self/fd/" + str(fd),
                        "--", "/usr/sbin/nft", "--stateless", "--numeric-priority",
                        "list", "ruleset")
        assert kwargs["pass_fds"] == (fd,) and kwargs["close_fds"]
        assert kwargs["shell"] is False
        return real_popen([sys.executable, "-c", payload], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", popen)
    try:
        if fault == "none":
            assert egress._read_namespace_rules(fd) == "fixed\n"
        else:
            with pytest.raises(NativeEgressCandidateError, match=(
                    "LIST_TOO_LARGE" if fault == "large" else "LIST_REFUSED")):
                egress._read_namespace_rules(fd)
    finally:
        os.close(fd)
    assert len(calls) == 1



@pytest.mark.parametrize("fault", ["none", "unchanged", "identity", "foreign", "check",
                                    "drift", "owner", "post-drift", "syntax"])
def test_fixed_namespace_replacement_retains_one_descriptor_and_checks_exact_rules(
        monkeypatch, fault):
    import contextlib
    from repocache import server_native_egress_candidate_v1 as egress

    doc, raw = fixture()
    old = egress.render_namespace_egress_candidate(
        doc, generation=1, http_fragment=raw, worker_uid=987)["nft_candidate"]
    doc, raw = fixture(both=False)
    new = egress.render_namespace_egress_candidate(
        doc, generation=1, http_fragment=raw, worker_uid=987)["nft_candidate"]
    identity = (17, 29)
    fd = 42
    observed = [old + ("table ip foreign {}\n" if fault == "foreign" else "")]
    calls = []
    held = [False]

    @contextlib.contextmanager
    def scope():
        held[0] = True
        try:
            yield fd, identity, lambda: calls.append("descriptor")
        finally:
            held[0] = False

    def owner():
        assert held[0]
        calls.append("owner")
        if fault == "owner" and True in calls:
            raise NativeEgressCandidateError("OWNER_REFUSED")

    def read(got):
        assert held[0] and got == fd
        calls.append("read")
        return observed[0]

    def batch(got, text, *, validate_only):
        assert held[0] and got == fd
        assert text == "delete table inet repocache_egress\n" + new
        calls.append(validate_only)
        if validate_only:
            if fault == "check":
                raise NativeEgressCandidateError("CHECK_REFUSED")
            if fault == "drift":
                observed[0] = new
        else:
            observed[0] = old if fault == "post-drift" else new

    monkeypatch.setattr(egress, "_fixed_namespace_scope", scope)
    monkeypatch.setattr(egress, "_read_namespace_rules", read)
    monkeypatch.setattr(egress, "_run_namespace_batch", batch)
    options = dict(namespace_identity=(17, 30) if fault == "identity" else identity,
                   recheck_owned=owner)
    if fault in ("none", "unchanged"):
        proposed = old if fault == "unchanged" else new
        result = egress._replace_fixed_namespace_egress(old, proposed, **options)
        assert result["status"] == ("NAMESPACE_EGRESS_UNCHANGED" if fault == "unchanged"
                                    else "NAMESPACE_EGRESS_REPLACEMENT_OBSERVED")
        assert not result["authorizes_catalog_publication"]
        assert not result["authorizes_nginx_activation"]
        assert not result["runtime_egress_verified"]
        assert observed[0] == proposed
        assert [x for x in calls if type(x) is bool] == ([] if fault == "unchanged" else [True, False])
    else:
        proposed = new + "flush ruleset\n" if fault == "syntax" else new
        with pytest.raises(NativeEgressCandidateError):
            egress._replace_fixed_namespace_egress(old, proposed, **options)
        assert [x for x in calls if type(x) is bool] == (
            [True, False] if fault == "post-drift" else
            [True] if fault in ("check", "drift", "owner") else [])
    assert not held[0]


@pytest.mark.parametrize("validate_only", [True, False])
def test_fixed_batch_uses_retained_fd_and_fixed_argv(monkeypatch, validate_only):
    import subprocess
    from types import SimpleNamespace
    from repocache import server_native_egress_candidate_v1 as egress
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert kwargs["pass_fds"] == (42,)
        assert kwargs["shell"] is False and kwargs["close_fds"] is True
        assert kwargs["input"] == b"fixed batch\n" and kwargs["timeout"] == 10
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", run)
    egress._run_namespace_batch(42, "fixed batch\n", validate_only=validate_only)
    assert calls == [("/usr/bin/nsenter", "--net=/proc/self/fd/42", "--",
                      "/usr/sbin/nft", *(("-c",) if validate_only else ()), "-f", "-")]


@pytest.mark.parametrize("fault", [
    "none", "identity", "foreign", "identical", "check", "drift",
    "owner", "post-drift", "syntax",
])
def test_fixed_namespace_initialization_requires_empty_owned_scope(monkeypatch, fault):
    import contextlib
    from repocache import server_native_egress_candidate_v1 as egress

    doc, raw = fixture()
    expected = egress.render_namespace_egress_candidate(
        doc, generation=1, http_fragment=raw, worker_uid=987)["nft_candidate"]
    identity = (17, 29)
    observed = [("table ip foreign {}\n" if fault == "foreign" else
                 expected if fault == "identical" else "")]
    events = []
    held = [False]

    @contextlib.contextmanager
    def scope():
        held[0] = True
        try:
            yield 42, identity, lambda: events.append("descriptor")
        finally:
            held[0] = False

    def owner():
        assert held[0]
        events.append("owner")
        if fault == "owner" and True in events:
            raise NativeEgressCandidateError("OWNER_REFUSED")

    def read(fd):
        assert held[0] and fd == 42
        events.append("read")
        return observed[0]

    def batch(fd, raw, *, validate_only):
        assert held[0] and fd == 42 and raw == expected
        events.append(validate_only)
        if validate_only:
            if fault == "check":
                raise NativeEgressCandidateError("CHECK_REFUSED")
            if fault == "drift":
                observed[0] = expected
        else:
            observed[0] = "" if fault == "post-drift" else expected

    monkeypatch.setattr(egress, "_fixed_namespace_scope", scope)
    monkeypatch.setattr(egress, "_read_namespace_rules", read)
    monkeypatch.setattr(egress, "_run_namespace_batch", batch)
    options = dict(namespace_identity=(17, 30) if fault == "identity" else identity,
                   recheck_owned=owner)
    proposed = expected + "flush ruleset\n" if fault == "syntax" else expected
    if fault == "none":
        result = egress._initialize_fixed_namespace_egress(proposed, **options)
        assert result["status"] == "NAMESPACE_EGRESS_INITIALIZATION_OBSERVED"
        assert not result["authorizes_catalog_publication"]
        assert not result["authorizes_nginx_activation"]
        assert not result["runtime_egress_verified"]
        assert observed[0] == expected
        assert [x for x in events if type(x) is bool] == [True, False]
        events.clear()
        with pytest.raises(NativeEgressCandidateError, match="NAMESPACE_NOT_EMPTY"):
            egress._initialize_fixed_namespace_egress(proposed, **options)
        assert [x for x in events if type(x) is bool] == []
    else:
        with pytest.raises(NativeEgressCandidateError):
            egress._initialize_fixed_namespace_egress(proposed, **options)
        assert [x for x in events if type(x) is bool] == (
            [True, False] if fault == "post-drift" else
            [True] if fault in ("check", "drift", "owner") else [])
    assert not held[0]


@pytest.mark.parametrize("fault", [
    "none", "before-nft", "after-nft", "foreign", "identical", "boot",
    "namespace", "generation", "profile", "executable", "manifest", "rules",
])
def test_boot_egress_receipt_binds_intent_and_exact_resume(tmp_path, monkeypatch, fault):
    import contextlib
    import os
    from repocache import server_native_egress_candidate_v1 as egress

    doc, raw = fixture()
    expected = egress.render_namespace_egress_candidate(
        doc, generation=1, http_fragment=raw, worker_uid=987)["nft_candidate"]
    identity = [17, 29]
    boot = ["1f8f3d9c-17c2-4a45-a013-1d781b9796af"]
    observed = ["table ip foreign {}\n" if fault == "foreign" else
                expected if fault == "identical" else ""]
    writes = []
    state = tmp_path / "var/lib/repocache/server"
    state.mkdir(parents=True)
    state.chmod(0o700)
    receipt = state / egress._BOOT_EGRESS_RECEIPT
    rootfd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    statefd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)

    @contextlib.contextmanager
    def scope():
        yield 42, tuple(identity), lambda: None

    def read(fd):
        assert fd == 42
        return observed[0]

    def batch(fd, raw, *, validate_only):
        assert fd == 42 and raw == expected and receipt.is_file()
        writes.append(validate_only)
        if not validate_only:
            if fault == "before-nft" and writes.count(False) == 1:
                raise OSError("simulated interruption after receipt")
            observed[0] = expected
            if fault == "after-nft" and writes.count(False) == 1:
                raise OSError("simulated interruption after mutation")

    monkeypatch.setattr(egress, "_fixed_namespace_scope", scope)
    monkeypatch.setattr(egress, "_current_boot_id", lambda: boot[0])
    monkeypatch.setattr(egress, "_read_namespace_rules", read)
    monkeypatch.setattr(egress, "_run_namespace_batch", batch)

    def prepare(allow=True, **changes):
        options = dict(namespace_identity=tuple(identity), generation=1,
                       generation_manifest_sha256="a" * 64,
                       profile_receipt_sha256="b" * 64,
                       executable_receipt_sha256="c" * 64,
                       recheck_owned=lambda: None, allow_prepare=allow)
        options.update(changes)
        return egress._prepare_boot_egress_locked(rootfd, statefd, expected, **options)

    try:
        if fault in ("foreign", "identical"):
            with pytest.raises(NativeEgressCandidateError, match="BOOT_INTENT_REQUIRED"):
                prepare()
            assert not receipt.exists() and not writes
            return
        with pytest.raises(NativeEgressCandidateError, match="BOOT_INTENT_REQUIRED"):
            prepare(False)
        assert not receipt.exists()
        if fault in ("before-nft", "after-nft"):
            with pytest.raises(NativeEgressCandidateError, match="BOOT_PREPARATION_REFUSED"):
                prepare()
            assert receipt.is_file()
            durable = receipt.read_bytes()
            inode = receipt.stat().st_ino
            if fault == "before-nft":
                with pytest.raises(NativeEgressCandidateError, match="BOOT_POLICY_PENDING"):
                    prepare(False)
            else:
                assert prepare(False)["ruleset_shape_matches"]
        result = prepare()
        assert result["status"] == "NATIVE_EGRESS_BOOT_RECEIPT_VERIFIED"
        assert not result["authorizes_nginx_activation"]
        assert not result["authorizes_catalog_publication"]
        assert not result["runtime_egress_verified"]
        assert observed[0] == expected
        assert prepare(False) == result == prepare()
        if fault in ("before-nft", "after-nft"):
            assert receipt.read_bytes() == durable and receipt.stat().st_ino == inode
        assert writes == ([True, False, True, False] if fault == "before-nft" else [True, False])
        saved = receipt.read_bytes()
        changes = {}
        if fault == "boot":
            boot[0] = "2f8f3d9c-17c2-4a45-a013-1d781b9796af"
        elif fault == "namespace":
            identity[1] += 1
        elif fault == "generation":
            changes["generation"] = 2
        elif fault == "profile":
            changes["profile_receipt_sha256"] = "d" * 64
        elif fault == "executable":
            changes["executable_receipt_sha256"] = "d" * 64
        elif fault == "manifest":
            changes["generation_manifest_sha256"] = "d" * 64
        elif fault == "rules":
            observed[0] += "table ip foreign {}\n"
        if fault in ("boot", "namespace", "generation", "profile", "executable", "manifest", "rules"):
            writes.clear()
            with pytest.raises(NativeEgressCandidateError):
                prepare(**changes)
            assert receipt.read_bytes() == saved and not writes
    finally:
        os.close(statefd)
        os.close(rootfd)


@pytest.mark.parametrize("fault", ["none", "before-replace", "after-replace", "foreign-stage",
                                    "foreign-archive", "same-boot", "generation",
                                    "not-empty", "missing-current"])
def test_boot_rollover_preserves_prior_receipt_and_resumes_exactly(tmp_path, monkeypatch, fault):
    import contextlib
    import json
    import os
    from repocache import server_native_egress_candidate_v1 as egress

    doc, raw = fixture()
    expected = egress.render_namespace_egress_candidate(
        doc, generation=1, http_fragment=raw, worker_uid=987)["nft_candidate"]
    old_boot = "1f8f3d9c-17c2-4a45-a013-1d781b9796af"
    boot = [old_boot]
    identity = [17, 29]
    observed = [""]
    writes = []
    state = tmp_path / "var/lib/repocache/server"
    state.mkdir(parents=True)
    state.chmod(0o700)
    receipt = state / egress._BOOT_EGRESS_RECEIPT
    archive = state / (egress._BOOT_EGRESS_HISTORY_PREFIX + old_boot)
    stage = state / egress._BOOT_EGRESS_ROLLOVER
    rootfd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    statefd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)

    @contextlib.contextmanager
    def scope():
        yield 42, tuple(identity), lambda: None

    def batch(fd, raw, *, validate_only):
        assert fd == 42 and raw == expected and receipt.is_file()
        writes.append(validate_only)
        if not validate_only:
            observed[0] = expected

    monkeypatch.setattr(egress, "_fixed_namespace_scope", scope)
    monkeypatch.setattr(egress, "_current_boot_id", lambda: boot[0])
    monkeypatch.setattr(egress, "_read_namespace_rules", lambda fd: observed[0])
    monkeypatch.setattr(egress, "_run_namespace_batch", batch)

    def prepare(allow=True, rollover=False, generation=1):
        return egress._prepare_boot_egress_locked(
            rootfd, statefd, expected, namespace_identity=tuple(identity),
            generation=generation, generation_manifest_sha256="a" * 64,
            profile_receipt_sha256="b" * 64, executable_receipt_sha256="c" * 64,
            recheck_owned=lambda: None, allow_prepare=allow,
            allow_boot_rollover=rollover)

    try:
        prepare()
        saved = receipt.read_bytes()
        writes.clear()
        if fault != "same-boot":
            boot[0] = "2f8f3d9c-17c2-4a45-a013-1d781b9796af"
        identity[1] += 1
        observed[0] = expected if fault == "not-empty" else ""
        with pytest.raises(NativeEgressCandidateError, match="BOOT_RECEIPT_MISMATCH"):
            prepare()
        assert receipt.read_bytes() == saved and not archive.exists() and not writes
        if fault == "foreign-stage":
            stage.write_bytes(b"foreign")
            stage.chmod(0o600)
        elif fault == "foreign-archive":
            archive.write_bytes(b"foreign")
            archive.chmod(0o600)
        elif fault == "missing-current":
            archive.write_bytes(saved)
            archive.chmod(0o600)
            receipt.unlink()
        if fault in ("foreign-stage", "foreign-archive", "same-boot",
                     "generation", "not-empty", "missing-current"):
            with pytest.raises(NativeEgressCandidateError):
                prepare(rollover=True, generation=2 if fault == "generation" else 1)
            assert not writes
            if fault == "missing-current":
                assert not receipt.exists() and archive.read_bytes() == saved
            else:
                assert receipt.read_bytes() == saved
            if fault == "foreign-stage":
                assert stage.read_bytes() == b"foreign" and not archive.exists()
            if fault == "foreign-archive":
                assert archive.read_bytes() == b"foreign" and not stage.exists()
            return
        if fault in ("before-replace", "after-replace"):
            actual_replace = os.replace
            def interrupted(*args, **kwargs):
                if fault == "after-replace":
                    actual_replace(*args, **kwargs)
                raise OSError("interrupted at atomic publication")
            with monkeypatch.context() as m:
                m.setattr(os, "replace", interrupted)
                with pytest.raises(NativeEgressCandidateError, match="BOOT_PREPARATION_REFUSED"):
                    prepare(rollover=True)
            assert archive.read_bytes() == saved and not writes
            if fault == "before-replace":
                assert receipt.read_bytes() == saved and stage.is_file()
                staged_inode = stage.stat().st_ino
            else:
                assert json.loads(receipt.read_bytes())["boot_id"] == boot[0]
                assert not stage.exists()
                staged_inode = receipt.stat().st_ino
                with pytest.raises(NativeEgressCandidateError, match="BOOT_POLICY_PENDING"):
                    prepare(False)
        result = prepare(rollover=True)
        assert result["boot_id"] == boot[0]
        assert result["namespace_inode"] == identity[1]
        assert archive.read_bytes() == saved
        assert json.loads(receipt.read_bytes())["boot_id"] == boot[0]
        assert not stage.exists() and writes == [True, False]
        if fault in ("before-replace", "after-replace"):
            assert receipt.stat().st_ino == staged_inode
        assert prepare(False) == result == prepare()
        assert writes == [True, False]
    finally:
        os.close(statefd)
        os.close(rootfd)


@pytest.mark.parametrize("fault", ["none", "foreign", "parent-drift", "boot-drift",
                                    "ip-drift", "owner-drift", "extra-link",
                                    "rules", "link-up-failed"])
def test_create_namespace_is_absent_only_and_loopback_only(monkeypatch, fault):
    import contextlib
    from repocache import server_native_egress_candidate_v1 as egress
    from repocache import server_root_control_host_preflight_v1 as host

    calls = []
    created = [False]
    up = [False]
    boot = "1f8f3d9c-17c2-4a45-a013-1d781b9796af"
    parents = []
    monkeypatch.setattr(host, "require_native_host_preconditions", lambda: None)
    monkeypatch.setattr(egress, "_current_boot_id", lambda: (
        "2f8f3d9c-17c2-4a45-a013-1d781b9796af"
        if fault == "boot-drift" and created[0] else boot))
    monkeypatch.setattr(egress, "_safe_namespace_ip_program", lambda: (
        (2,) if fault == "ip-drift" and created[0] else (1,)))

    def parent():
        parents.append(1)
        if fault == "foreign" or created[0]:
            raise NativeEgressCandidateError("NAMESPACE_DIRECTORY_NOT_EMPTY")
        return (1, 2 if fault == "parent-drift" and len(parents) == 2 else 1)

    def owner():
        if fault == "owner-drift" and created[0]:
            raise NativeEgressCandidateError("OWNER_REFUSED")

    @contextlib.contextmanager
    def scope():
        assert created[0]
        yield 42, (17, 29), lambda: None

    def native(fd=None):
        calls.append(fd)
        if fd is None:
            created[0] = True
        elif fault != "link-up-failed":
            up[0] = True

    def link(fd, *, up):
        assert fd == 42
        if fault == "extra-link" or up != is_up[0]:
            raise NativeEgressCandidateError("LOOPBACK_REFUSED")

    is_up = up
    monkeypatch.setattr(egress, "_empty_namespace_parent", parent)
    monkeypatch.setattr(egress, "_fixed_namespace_scope", scope)
    monkeypatch.setattr(egress, "_run_namespace_creation", native)
    monkeypatch.setattr(egress, "_require_loopback_only", link)
    monkeypatch.setattr(egress, "_read_namespace_rules",
                        lambda fd: "foreign" if fault == "rules" else "")
    if fault == "none":
        result = egress._create_fixed_loopback_namespace_locked(recheck_owned=owner)
        assert result["status"] == "NATIVE_EGRESS_FRESH_LOOPBACK_NAMESPACE_OBSERVED"
        assert result["boot_id"] == boot
        assert (result["namespace_device"], result["namespace_inode"]) == (17, 29)
        assert result["loopback_only_observed"] and result["empty_ruleset_observed"]
        assert not result["authorizes_nginx_activation"]
        assert not result["authorizes_catalog_publication"]
        assert calls == [None, 42]
        with pytest.raises(NativeEgressCandidateError, match="DIRECTORY_NOT_EMPTY"):
            egress._create_fixed_loopback_namespace_locked(recheck_owned=owner)
        assert calls == [None, 42]
    else:
        with pytest.raises(NativeEgressCandidateError):
            egress._create_fixed_loopback_namespace_locked(recheck_owned=owner)
        assert calls == ([] if fault in ("foreign", "parent-drift") else
                         [None, 42] if fault == "link-up-failed" else [None])


@pytest.mark.parametrize("fault", ["none", "extra", "wrong-type", "wrong-index",
                                    "down", "other-flags", "bad-json"])
def test_loopback_only_readback_requires_native_link_shape(monkeypatch, fault):
    import json
    from repocache import server_native_egress_candidate_v1 as egress
    row = {"ifindex": 1, "ifname": "lo", "link_type": "loopback",
           "flags": ["LOOPBACK", "UP", "LOWER_UP"]}
    if fault == "wrong-type":
        row["link_type"] = "ether"
    elif fault == "wrong-index":
        row["ifindex"] = 2
    elif fault == "down":
        row["flags"] = ["LOOPBACK"]
    elif fault == "other-flags":
        row["flags"].append("PROMISC")
    raw = json.dumps([row, row] if fault == "extra" else [row])
    def read(fd, command, *, maximum):
        assert fd == 42 and command == ("/usr/sbin/ip", "-j", "link", "show")
        assert maximum == 16384
        return "[" if fault == "bad-json" else raw
    monkeypatch.setattr(egress, "_bounded_namespace_output", read)
    if fault == "none":
        egress._require_loopback_only(42, up=True)
    else:
        with pytest.raises(NativeEgressCandidateError, match="LOOPBACK_REFUSED"):
            egress._require_loopback_only(42, up=True)


@pytest.mark.parametrize("fault", ["first", "explicit-missing", "stale", "implicit",
                                    "same-boot", "generation", "profile", "executable",
                                    "rules", "pending", "foreign-archive", "orphan-history"])
def test_fresh_boot_intent_preflight_is_read_only(tmp_path, monkeypatch, fault):
    import os
    from repocache import server_native_egress_candidate_v1 as egress
    from repocache.server_protected_state_store_v1 import _canonical

    old_boot = "1f8f3d9c-17c2-4a45-a013-1d781b9796af"
    new_boot = "2f8f3d9c-17c2-4a45-a013-1d781b9796af"
    boot = old_boot if fault == "same-boot" else new_boot
    monkeypatch.setattr(egress, "_current_boot_id", lambda: boot)
    rules = egress.render_bootstrap_egress_candidate(worker_uid=33)["nft_candidate"]
    previous = {
        "schema_version": 1, "boot_id": old_boot,
        "namespace_device": 17, "namespace_inode": 29,
        "generation": 0, "generation_manifest_sha256": "a"*64,
        "profile_receipt_sha256": "b"*64, "executable_receipt_sha256": "c"*64,
        "ruleset_sha256": hashlib.sha256(rules.encode("ascii")).hexdigest(),
        "authorizes_nginx_activation": False,
    }
    for kind, field, value in (
        ("generation", "generation", 1), ("profile", "profile_receipt_sha256", "d"*64),
        ("executable", "executable_receipt_sha256", "e"*64), ("rules", "ruleset_sha256", "f"*64),
    ):
        if fault == kind:
            previous[field] = value
    raw = _canonical(previous, limit=egress._BOOT_EGRESS_RECEIPT_MAX)
    receipt = tmp_path / egress._BOOT_EGRESS_RECEIPT
    archive = tmp_path / (egress._BOOT_EGRESS_HISTORY_PREFIX + old_boot)
    stage = tmp_path / egress._BOOT_EGRESS_ROLLOVER

    def place(path, content):
        path.write_bytes(content)
        path.chmod(0o600)

    if fault not in ("first", "explicit-missing", "orphan-history"):
        place(receipt, raw)
    if fault == "pending":
        place(stage, b"foreign")
    if fault == "foreign-archive":
        place(archive, b"foreign")
    if fault == "orphan-history":
        place(archive, raw)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        def invoke():
            return egress._fresh_boot_egress_intent_locked(
                fd, rules, generation=0, generation_manifest_sha256="a"*64,
                profile_receipt_sha256="b"*64, executable_receipt_sha256="c"*64,
                allow_boot_rollover=fault not in ("first", "implicit", "orphan-history"))
        if fault in ("first", "stale"):
            assert invoke() == (boot, raw if fault == "stale" else None)
        else:
            with pytest.raises(NativeEgressCandidateError):
                invoke()
        assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before
    finally:
        os.close(fd)
