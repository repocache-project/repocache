"""Strict native client responses; no successful inference from empty sockets."""
from __future__ import annotations

import json

import pytest

import repocache.server_native_root_control_client_v1 as client


def packet(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"))
            + "\n").encode("ascii")


def result(operation, status, *, generation=None):
    published = status == "APPLIED"
    return {
        "schema_version": 1,
        "status": status,
        "requested_operation": operation,
        "state_generation": generation,
        "transaction_completed": True,
        "nginx_reload_and_exposure_observed": published,
        "active_catalog_published": published,
    }


@pytest.mark.parametrize("op,status,gen", [
    ("APPLY_V2", "APPLIED", 1),
    ("APPLY_V2", "UNCHANGED", 2),
    ("RECOVER_V2", "RECOVERED", None),
    ("RECOVER_V2", "CLEAN", None),
])
def test_only_exact_accepted_success_is_parsed(op, status, gen):
    expected = result(op, status, generation=gen)
    assert client._parse_native_reply(packet(expected), operation=op) == expected


@pytest.mark.parametrize("broken", [
    (b"", "RESPONSE_INVALID"),
    (b'{}', "RESPONSE_INVALID"),
    (b'{} \n', "RESPONSE_NONCANONICAL"),
    (b'{"schema_version":1,"schema_version":1}\n', "RESPONSE_INVALID"),
    (packet(result("APPLY_V2", "APPLIED", generation=True)), "RESPONSE_UNEXPECTED"),
    (packet(result("RECOVER_V2", "RECOVERED", generation=2)), "RESPONSE_UNEXPECTED"),
    (packet(result("APPLY_V2", "CLEAN")), "RESPONSE_UNEXPECTED"),
    (packet(result("RECOVER_V2", "APPLIED", generation=1)), "RESPONSE_UNEXPECTED"),
    (packet({**result("APPLY_V2", "APPLIED", generation=1),
             "active_catalog_published": False}), "RESPONSE_UNEXPECTED"),
])
def test_reply_fails_closed(broken):
    raw, expected = broken
    with pytest.raises(client.NativeRootControlClientError, match=expected):
        client._parse_native_reply(raw, operation="APPLY_V2"
                                   if b'APPLY' in raw else "RECOVER_V2")


def test_operation_denied_is_not_success():
    denied = {
        "schema_version": 1, "status": "DENIED",
        "requested_operation": "APPLY_V2",
        "code": "NATIVE_V2_OPERATION_REFUSED",
        "transaction_completed": False,
    }
    with pytest.raises(client.NativeRootControlClientError,
                       match="OPERATION_REFUSED"):
        client._parse_native_reply(packet(denied), operation="APPLY_V2")


def test_unsupported_operation_refused_before_accessing_socket(monkeypatch):
    monkeypatch.setattr(client, "_validate_parent_and_socket",
                        lambda: pytest.fail("must not access socket"))
    with pytest.raises(client.NativeRootControlClientError,
                       match="OPERATION_REFUSED"):
        client.request_native_fixed_v2("RUN_SHELL")
