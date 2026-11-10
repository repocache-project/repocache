"""Native pre-reload composition is a non-authorizing observation only."""
from __future__ import annotations

import inspect

import pytest

import repocache.server_root_control_pre_reload_v1 as gate


def _good(monkeypatch, *, unit_changed=False):
    calls = []
    monkeypatch.setattr(gate.os, "getuid", lambda: 0)
    monkeypatch.setattr(gate.os, "geteuid", lambda: 0)
    monkeypatch.setattr(gate.os, "getresuid", lambda: (0, 0, 0))

    def host():
        calls.append("host")
        return {
            "status": "NATIVE_HOST_NECESSARY_PRECONDITIONS_ONLY",
            "host_root_provenance_verified": False,
            "authorizes_nginx_reload": False,
        }

    def unit(distribution):
        calls.append(("unit", distribution))
        n = sum(isinstance(c, tuple) and c[0] == "unit" for c in calls)
        return {
            "status": "NATIVE_NGINX_EFFECTIVE_READ_ONLY_OBSERVATION",
            "unit_name": "nginx.service",
            "main_pid_observed": 141 if unit_changed and n == 2 else 140,
            "vendor_unit_sha256": "a" * 64,
            "authorizes_nginx_reload": False,
        }

    def syntax():
        calls.append("syntax")
        return {
            "status": "NATIVE_INSTALLED_DEFAULT_NGINX_SYNTAX_ONLY",
            "default_config_syntax_observed": True,
            "authorizes_nginx_reload": False,
        }

    def full():
        calls.append("full")
        return {
            "status": "NATIVE_DEFAULT_NGINX_FULL_CONTEXT_BYTES_ONLY",
            "full_context_bytes_observed": True,
            "full_context_sha256": "b" * 64,
            "dump_size_bytes": 100,
            "authorizes_nginx_reload": False,
        }

    monkeypatch.setattr(gate, "require_native_host_preconditions", host)
    monkeypatch.setattr(gate, "inspect_effective_native_nginx_unit", unit)
    monkeypatch.setattr(gate, "inspect_installed_default_nginx_syntax_only", syntax)
    monkeypatch.setattr(gate, "inspect_installed_default_nginx_full_context_only", full)
    return calls


def test_fixed_read_only_prereload_order_and_no_authority(monkeypatch):
    calls = _good(monkeypatch)
    report = gate.inspect_native_nginx_pre_reload_consistency_only("debian")
    assert calls == [
        "host", ("unit", "debian"), "syntax", "full",
        ("unit", "debian"), "host",
    ]
    assert report["full_context_sha256"] == "b" * 64
    assert report["vendor_unit_sha256"] == "a" * 64
    assert report["effective_master_pid_observed"] == 140
    assert all(value is False for key, value in report.items()
               if key.startswith("authorizes_") or key.endswith("_verified"))
    assert "reload" not in report["status"].lower().replace("pre_reload", "")


@pytest.mark.parametrize("distribution", [None, "", "ubuntu", "Debian", True, "debian;rm"])
def test_invalid_distribution_denied_before_any_probe(monkeypatch, distribution):
    calls = _good(monkeypatch)
    with pytest.raises(gate.FixedPreReloadObservationError,
                       match="DISTRIBUTION_REFUSED"):
        gate.inspect_native_nginx_pre_reload_consistency_only(distribution)
    assert calls == []


@pytest.mark.parametrize("identity", [
    ("getuid", 1000), ("geteuid", 1000), ("getresuid", (0, 1000, 0)),
])
def test_no_mixed_root_ids(monkeypatch, identity):
    calls = _good(monkeypatch)
    monkeypatch.setattr(gate.os, identity[0], lambda: identity[1])
    with pytest.raises(gate.FixedPreReloadObservationError,
                       match="ROOT_REQUIRED"):
        gate.inspect_native_nginx_pre_reload_consistency_only("almalinux")
    assert calls == []


def test_unit_change_between_before_after_is_denied(monkeypatch):
    calls = _good(monkeypatch, unit_changed=True)
    with pytest.raises(gate.FixedPreReloadObservationError,
                       match="EFFECTIVE_UNIT_CHANGED"):
        gate.inspect_native_nginx_pre_reload_consistency_only("debian")
    assert ("unit", "debian") in calls


@pytest.mark.parametrize("stage,field,value,code", [
    ("host", "host_root_provenance_verified", True, "HOST_CONTEXT_UNVERIFIED"),
    ("unit", "authorizes_nginx_reload", True, "EFFECTIVE_UNIT_UNVERIFIED"),
    ("syntax", "default_config_syntax_observed", False, "SYNTAX_UNVERIFIED"),
    ("full", "dump_size_bytes", 0, "FULL_CONTEXT_UNVERIFIED"),
    ("full", "full_context_sha256", "not-a-digest", "FULL_CONTEXT_UNVERIFIED"),
    ("full", "authorizes_nginx_reload", True, "FULL_CONTEXT_UNVERIFIED"),
])
def test_forged_or_invalid_observation_is_denied(monkeypatch, stage, field, value, code):
    _good(monkeypatch)
    target = {
        "host": "require_native_host_preconditions",
        "unit": "inspect_effective_native_nginx_unit",
        "syntax": "inspect_installed_default_nginx_syntax_only",
        "full": "inspect_installed_default_nginx_full_context_only",
    }[stage]
    old = getattr(gate, target)
    def forged(*args):
        result = old(*args)
        result[field] = value
        return result
    monkeypatch.setattr(gate, target, forged)
    with pytest.raises(gate.FixedPreReloadObservationError, match=code):
        gate.inspect_native_nginx_pre_reload_consistency_only("debian")


@pytest.mark.parametrize("stage,error,code", [
    ("host", gate.NativeHostPreflightError("PRIVATE_STRING"), "HOST_CONTEXT_REFUSED"),
    ("unit", gate.EffectiveNginxUnitError("PRIVATE_STRING"), "EFFECTIVE_UNIT_REFUSED"),
    ("syntax", gate.FixedNginxSyntaxError("PRIVATE_STRING"), "SYNTAX_REFUSED"),
    ("full", gate.FixedNginxFullContextError("PRIVATE_STRING"), "FULL_CONTEXT_REFUSED"),
])
def test_private_exception_redacted(monkeypatch, stage, error, code):
    _good(monkeypatch)
    target = {
        "host": "require_native_host_preconditions",
        "unit": "inspect_effective_native_nginx_unit",
        "syntax": "inspect_installed_default_nginx_syntax_only",
        "full": "inspect_installed_default_nginx_full_context_only",
    }[stage]
    def fail(*args):
        raise error
    monkeypatch.setattr(gate, target, fail)
    with pytest.raises(gate.FixedPreReloadObservationError, match=code) as caught:
        gate.inspect_native_nginx_pre_reload_consistency_only("almalinux")
    assert "PRIVATE_STRING" not in str(caught.value)


def test_neither_broker_nor_module_provides_a_reload_dispatcher():
    from repocache.server_root_control_worker_v1 import serve_one_fixed_request
    source = inspect.getsource(serve_one_fixed_request)
    assert "inspect_native_nginx_pre_reload_consistency_only" not in source
    assert "ROOT_TRANSACTION_NOT_IMPLEMENTED" in source
    assert "subprocess" not in inspect.getsource(gate)
