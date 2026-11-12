"""Read-only client helper contract prototype; NOT an installed root helper.

It exposes status and scoped source *filesystem inspection*, not full
repository validation. No apply/restore/recovery operation, write permission
delegation, install integration or implicit privilege escalation exists.

There is intentionally NO --root or arbitrary file-path option. A private
test-only root injection is guarded by source_preflight's marked /tmp fixture.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

import source_preflight as pre
import entry_approval_plan_sandbox as approval
import managed_registry_sandbox as registry
import source_entry_boundaries as boundaries


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's default message may echo credentials inside invalid args.
        raise _UsageError("Invalid helper arguments")


def _parser() -> _Parser:
    parser = _Parser(prog="repocache-client-helper-preview")
    parser.add_argument("--json", action="store_true", dest="global_json",
                        help="Print one finite JSON response")
    actions = parser.add_subparsers(dest="action", required=True)
    status = actions.add_parser("status",
                                help="Show the capabilities of this read-only prototype")
    status.add_argument("--json", action="store_true", dest="local_json")
    inspect = actions.add_parser(
        "inspect-source",
        help="Inspect an allowlisted source filesystem inode, not repository trust",
    )
    inspect.add_argument("--source", required=True, metavar="RELATIVE_PATH",
                         help="Allowlisted relative APT/DNF source path")
    inspect.add_argument("--json", action="store_true", dest="local_json")
    validate = actions.add_parser(
        "validate-source",
        help="Check conservative APT/DNF structure without write authority",
    )
    validate.add_argument("--source", required=True, metavar="RELATIVE_PATH")
    validate.add_argument("--json", action="store_true", dest="local_json")
    verify = actions.add_parser(
        "verify-route-approval",
        help="Check exact approved route digest in protected sandbox state",
    )
    verify.add_argument("--candidate", required=True, metavar="ID")
    verify.add_argument("--route-sha256", required=True, metavar="SHA256")
    verify.add_argument("--json", action="store_true", dest="local_json")
    return parser


def _failure(code: str, message: str, operation: str = "unknown") -> dict:
    return {
        "schema_version": 1,
        "ok": False,
        "operation": operation,
        "read_only": True,
        "write_eligible": False,
        "error": {"code": code, "message": message},
    }


def _success(operation: str, **fields) -> dict:
    return {
        "schema_version": 1,
        "ok": True,
        "operation": operation,
        "read_only": True,
        "write_eligible": False,
        **fields,
    }


def _emit(document: dict, json_output: bool) -> None:
    if json_output:
        print(json.dumps(document, ensure_ascii=True, sort_keys=True,
                         separators=(",", ":")))
        return
    if not document["ok"]:
        print("%s: %s" % (document["error"]["code"],
                          document["error"]["message"]))
    elif document["operation"] == "status":
        print("Read-only helper prototype; no installed privileges or write operations.")
    elif document["operation"] == "verify-route-approval":
        print("Exact route approved in private sandbox; native writes disabled.")
    elif document["operation"] == "validate-source":
        print("Structure subset validated; native trust and writes NOT verified.")
    else:
        print("Filesystem preflight passed; repository trust and apply are NOT verified.")


def main(argv: Sequence[str] | None = None, *,
         _test_root: Path | None = None) -> int:
    """Execute a deterministic read-only prototype.

    _test_root is reserved for explicit /tmp fixtures within automated tests.
    It is NOT a CLI flag, is never read from an environment variable, and the
    preflight component independently verifies its private marker and inode.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    wants_json = "--json" in arguments
    parser = _parser()
    try:
        args = parser.parse_args(arguments)
    except _UsageError:
        _emit(_failure("INVALID_ARGUMENTS", "Invalid helper arguments"), wants_json)
        return 2
    json_output = args.global_json or getattr(args, "local_json", False)
    if args.action == "status":
        _emit(_success(
            "status",
            capabilities=["status", "inspect-source", "validate-source",
                          "verify-route-approval"],
            installed=False,
            source_writes_supported=False,
            semantic_repository_validation_supported=False,
        ), json_output)
        return 0


    if args.action == "verify-route-approval":
        operation = "verify-route-approval"
        # No production approval can derive from lab-only protected JSON.
        if _test_root is None:
            _emit(_failure("NOT_INSTALLED",
                           "No native route approval helper is installed",
                           operation), json_output)
            return 3
        if os.geteuid() != 0:
            _emit(_failure("ROOT_REQUIRED",
                           "Protected route approval requires root",
                           operation), json_output)
            return 3
        if (not registry.HEX_ID.fullmatch(args.candidate)
                or not registry.DIGEST.fullmatch(args.route_sha256)):
            _emit(_failure("INVALID_ARGUMENTS", "Invalid helper arguments",
                           operation), json_output)
            return 2
        try:
            root = Path(_test_root)
            candidate = approval._candidate(root, args.candidate)
            decision = approval._read_approval(root, args.candidate)
            if (decision["source_file_sha256"] != candidate["file_sha256"]
                    or decision["source_entry_sha256"] != candidate["entry_sha256"]
                    or decision["route_sha256"] != args.route_sha256):
                raise approval.ApprovalRefused("Route approval is not applicable")
            approval._snapshot(root, candidate)
        except (approval.ApprovalRefused, registry.RegistryRefused,
                pre.PreflightError, OSError, ValueError):
            _emit(_failure("ROUTE_APPROVAL_REFUSED",
                           "Protected route approval or source baseline refused",
                           operation), json_output)
            return 3
        _emit(_success(
            operation,
            route_approval="exact-route-matched",
            source_baseline_verified=True,
            source_contents_returned=False,
            approved_route_returned=False,
            approval_scope="sandbox-only",
            native_trust_verified=False,
            native_fallback_verified=False,
            installed=False,
        ), json_output)
        return 0


    if args.action == "validate-source":
        operation = "validate-source"
        root = Path("/") if _test_root is None else Path(_test_root)
        if root == Path("/") and os.geteuid() != 0:
            _emit(_failure("ROOT_REQUIRED",
                           "Native source validation requires root",
                           operation), json_output)
            return 3
        try:
            observed = pre.inspect_source(args.source, root=root)
            body = registry._source_bytes(root, args.source, observed)
            found = boundaries.boundaries(args.source, body)
            if (not found or len(found) > 128
                    or not all(item["structure_subset_pass"] for item in found)
                    or len({item["kind"] for item in found}) != 1):
                raise boundaries.EntryRefused("Unrecognized source structure")
            if pre.inspect_source(args.source, root=root) != observed:
                raise pre.PreflightError("Repository source drift")
        except (pre.PreflightError, registry.RegistryRefused,
                boundaries.EntryRefused, OSError, ValueError):
            _emit(_failure("SOURCE_STRUCTURE_REFUSED",
                           "Repository source structural validation refused",
                           operation), json_output)
            return 3
        _emit(_success(
            operation,
            filesystem_preflight="pass",
            structural_subset_verified=True,
            source_format=found[0]["kind"],
            repository_entries=len(found),
            extended_attributes_present=observed["extended_attributes_present"],
            source_contents_returned=False,
            source_path_returned=False,
            native_syntax_verified=False,
            package_signatures_verified=False,
            upstream_fallback_verified=False,
            managed_ownership_verified=False,
            installed=False,
        ), json_output)
        return 0

    # Do not confuse filesystem inspection with APT/DNF semantic validation
    # or with ownership authorization for a source transaction.
    if args.action == "inspect-source":
        root = Path("/") if _test_root is None else Path(_test_root)
        if root == Path("/") and os.geteuid() != 0:
            _emit(_failure("ROOT_REQUIRED",
                           "Native filesystem source inspection requires root",
                           "inspect-source"), json_output)
            return 3
        try:
            observed = pre.inspect_source(args.source, root=root)
        except (pre.PreflightError, OSError, ValueError):
            _emit(_failure(
                "SOURCE_PREFLIGHT_REFUSED",
                "Repository source filesystem preflight refused",
                "inspect-source",
            ), json_output)
            return 3
        _emit(_success(
            "inspect-source",
            filesystem_preflight="pass",
            extended_attributes_present=observed["extended_attributes_present"],
            source_contents_returned=False,
            source_path_returned=False,
            repository_syntax_verified=False,
            package_signatures_verified=False,
            upstream_fallback_verified=False,
            managed_ownership_verified=False,
        ), json_output)
        return 0

    _emit(_failure("INVALID_ARGUMENTS", "Invalid helper arguments"),
          json_output)
    return 2


if __name__ == "__main__":
    sys.exit(main())
