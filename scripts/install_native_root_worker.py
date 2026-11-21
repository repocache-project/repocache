#!/usr/bin/env python3
"""Place the authenticated fixed worker and units before native activation.

Run from the independently reviewed checkout on an authorized host. This
operation prepares the fixed server namespace and places the authenticated
worker. It never reloads or enables a service.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

if __name__ == "__main__":
    checkout = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(checkout / "src"), str(checkout)]

from repocache import signatures, upgrade
from repocache.server_install_v1 import MAX_DOCUMENT_BYTES, parse_install_bytes
from repocache.server_protected_namespace_bootstrap_v1 import bootstrap_protected_namespace_under_root
from repocache.server_locked_manifest_reconcile_v1 import (
    _validate_proposed_v2_snapshot, preview_proposed_v2_state_transition,
)
from repocache.server_repository_reconcile_v1 import plan_declarative_reconciliation
from repocache.server_native_v2_transaction_v1 import _no_conflicting_pending, _write_private
from repocache.server_proposed_state_v2_store import _read_v2
from repocache.server_protected_state_store_v1 import _canonical, _locked, _unlink_known
from repocache.server_root_control_fixed_candidate_v1 import (
    _MAX_ENVELOPE, _MAX_STATE, _NAME as _PROPOSAL, _canonical_json, _proposal,
)
from repocache.server_root_control_host_preflight_v1 import require_native_host_preconditions
from repocache.server_native_root_control_entrypoint_v1 import _native_distro
from repocache.server_repository_plan_v1 import _canonical_identity, propose_automatic_repository_id
from scripts import stage_native_root_worker as stage


_MARKER = ".native-worker-placement."
_TEMP = ".repocache-worker-part-"
_UNIT_DIRECTORY = ("etc", "systemd", "system")


def _reject(reason: str) -> None:
    raise stage.WorkerStageError("WORKER_PLACEMENT_" + reason)


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _named(directory: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _attribute_check(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0:
        _reject("FOREIGN_FILE")


def _check_marker(info: os.stat_result) -> None:
    _attribute_check(info)
    if info.st_size or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        _reject("FOREIGN_MARKER")


def _create_marker(directory: int, name: str) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)


def _exact_file(
    directory: int, name: str, data: bytes, mode: int, *,
    allow_partial: bool = False, links: int = 1,
) -> os.stat_result:
    initial = _named(directory, name)
    if initial is None:
        _reject("MISSING_FILE")
    _attribute_check(initial)
    observed_mode = stat.S_IMODE(initial.st_mode)
    is_partial = allow_partial and observed_mode == 0o600
    if (initial.st_nlink != links or not 0 <= initial.st_size <= len(data)
            or (not is_partial and observed_mode != mode)):
        _reject("FILE_METADATA_MISMATCH")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(name, flags, dir_fd=directory), "rb") as stream:
        before = os.fstat(stream.fileno())
        _attribute_check(before)
        if _identity(before) != _identity(initial) or before.st_mode != initial.st_mode:
            _reject("FILE_CHANGED")
        raw = stream.read(len(data) + 1)
        after = os.fstat(stream.fileno())
    named = _named(directory, name)
    if (named is None or _identity(named) != _identity(after)
            or before.st_mode != after.st_mode or before.st_nlink != after.st_nlink
            or before.st_size != after.st_size or before.st_ctime_ns != after.st_ctime_ns
            or before.st_mtime_ns != after.st_mtime_ns):
        _reject("FILE_CHANGED")
    matches = data.startswith(raw) if is_partial else raw == data
    if not matches:
        _reject("FILE_CONTENT_MISMATCH")
    return after


def _finish_link(directory: int, target: str, part: str, data: bytes, mode: int) -> None:
    final = _exact_file(directory, target, data, mode, links=2)
    staged = _exact_file(directory, part, data, mode, links=2)
    if _identity(final) != _identity(staged):
        _reject("FOREIGN_PARTIAL_LINK")
    os.unlink(part, dir_fd=directory)
    os.fsync(directory)
    _exact_file(directory, target, data, mode)


def _place_file(directory: int, name: str, raw: bytes, mode: int) -> None:
    part = _TEMP + name
    installed = _named(directory, name)
    staged = _named(directory, part)
    if installed is not None:
        if staged is not None:
            _finish_link(directory, name, part, raw, mode)
        else:
            _exact_file(directory, name, raw, mode)
        return
    if staged is not None:
        # Only the current, signed placement's interrupted prefix may be
        # removed. A foreign file at either name blocks placement.
        _exact_file(directory, part, raw, mode, allow_partial=True)
        os.unlink(part, dir_fd=directory)
    stage._write(directory, part, raw, mode)
    os.link(part, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
    os.fsync(directory)
    _finish_link(directory, name, part, raw, mode)


def _open_directory(parent: int, name: str, stack: ExitStack) -> int:
    fd = os.open(name, stage._DIRECTORY, dir_fd=parent)
    stack.callback(os.close, fd)
    stage._protected_directory(fd)
    return fd


def _worker_directory(usr: int, stack: ExitStack, *, create: bool = False) -> int | None:
    directory = usr
    for name in ("libexec", "repocache"):
        parent = directory
        try:
            directory = _open_directory(parent, name, stack)
        except FileNotFoundError:
            if not create:
                return None
            os.mkdir(name, mode=0o755, dir_fd=parent)
            directory = _open_directory(parent, name, stack)
        if create:
            # On recovery, make an earlier mkdir durable even if that
            # process was interrupted before its directory sync.
            os.fsync(directory)
            os.fsync(parent)
    return directory


def _systemd_unit_paths() -> tuple[str, ...]:
    result = subprocess.run(
        ["/usr/bin/systemctl", "--system", "--no-pager", "show", "--property=UnitPath", "--value"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        cwd="/", timeout=12, check=False,
    )
    if result.returncode or not 1 <= len(result.stdout) <= 8192:
        _reject("UNIT_PATH_UNVERIFIED")
    paths = tuple(result.stdout.decode("ascii").split())
    if ("/etc/systemd/system" not in paths or len(paths) > 64
            or any(re.fullmatch(r"(?:/[A-Za-z0-9_.-]+)+", path) is None
                   or any(part in (".", "..") for part in path.split("/")) for path in paths)):
        _reject("UNIT_PATH_UNVERIFIED")
    return paths


def _reject_conflicting_units(root: Path, unit_paths: tuple[str, ...]) -> None:
    for path in unit_paths:
        directory = root.joinpath(*path[1:].split("/"))
        for unit in stage.UNITS:
            names = [unit + ".d", "repocache-" + Path(unit).suffix + ".d"]
            if path != "/etc/systemd/system":
                names.append(unit)
            for name in names:
                try:
                    (directory / name).lstat()
                except FileNotFoundError:
                    continue
                _reject("FOREIGN_UNIT_OR_OVERRIDE")
        try:
            entries = tuple(directory.iterdir())
        except FileNotFoundError:
            continue
        for entry in entries:
            if entry.name.endswith((".wants", ".requires", ".upholds")):
                for unit in stage.UNITS:
                    try:
                        (entry / unit).lstat()
                    except FileNotFoundError:
                        continue
                    _reject("FOREIGN_UNIT_DEPENDENCY")
            if entry.name not in stage.UNITS and entry.is_symlink():
                if Path(os.readlink(entry)).name in stage.UNITS:
                    _reject("FOREIGN_UNIT_ALIAS")


def _place_worker_files(
    root: Path, payloads: dict[str, bytes], receipt: dict, *, unit_paths: tuple[str, ...],
    prepare_namespace: bool = False,
) -> None:
    digest = hashlib.sha256(stage._json_line(receipt)).hexdigest()
    pending = _MARKER + "pending-" + digest
    complete = _MARKER + "complete-" + digest
    with ExitStack() as stack:
        fd = os.open(root, stage._DIRECTORY)
        stack.callback(os.close, fd)
        stage._protected_directory(fd)
        usr = _open_directory(fd, "usr", stack)
        units = fd
        for component in _UNIT_DIRECTORY:
            units = _open_directory(units, component, stack)
        if prepare_namespace:
            _reject_conflicting_units(root, unit_paths)
            # A fresh namespace must not be created around unowned files.
            # Existing namespaces are checked under the protected lock below.
            if not os.path.lexists(root / "var/lib/repocache"):
                worker = _worker_directory(usr, stack)
                if (any(_named(units, name) is not None
                        for unit in stage.UNITS for name in (unit, _TEMP + unit))
                        or (worker is not None and any(_named(worker, name) is not None
                            for name in (stage.WORKER, _TEMP + stage.WORKER)))
                        or os.path.lexists(root / "run/repocache/server-control.sock")):
                    _reject("FOREIGN_EXISTING_DESTINATION")
            bootstrap_protected_namespace_under_root(fd, owner_uid=0, public_catalog=True)
        with _locked(fd, 0) as state:
            markers = {name for name in os.listdir(state) if name.startswith(_MARKER)}
            if markers - {pending, complete}:
                _reject("OTHER_CANDIDATE")
            for name in markers:
                info = _named(state, name)
                if info is None:
                    _reject("MARKER_CHANGED")
                _check_marker(info)
            _reject_conflicting_units(root, unit_paths)
            worker = _worker_directory(usr, stack)
            targets = [(units, unit) for unit in stage.UNITS]
            if worker is not None:
                targets.append((worker, stage.WORKER))
            if complete in markers:
                if worker is None:
                    _reject("MISSING_WORKER_DIRECTORY")
                if any(_named(directory, _TEMP + name) is not None
                       for directory, name in targets):
                    _reject("FOREIGN_PARTIAL_FILE")
                stage._audit_worker_files(root, payloads)
            else:
                try:
                    (root / "run/repocache/server-control.sock").lstat()
                except FileNotFoundError:
                    pass
                else:
                    _reject("LIVE_CONTROL_SOCKET")
                if pending not in markers:
                    for directory, name in targets:
                        if _named(directory, name) is not None or _named(directory, _TEMP + name) is not None:
                            _reject("FOREIGN_EXISTING_DESTINATION")
                    _create_marker(state, pending)
                worker = _worker_directory(usr, stack, create=True)
                _place_file(worker, stage.WORKER, payloads[stage.WORKER], 0o755)
                for unit in stage.UNITS:
                    _place_file(units, unit, payloads[unit], 0o644)
                stage._audit_worker_files(root, payloads)
                _create_marker(state, complete)
            final_pending = _named(state, pending)
            if final_pending is not None:
                _check_marker(final_pending)
                os.unlink(pending, dir_fd=state)
                os.fsync(state)


def install_authenticated_worker(
    assets: Path, *, commit: str, archive_sha256: str,
) -> dict:
    """Authenticated placement into fixed root paths, with no activation."""
    _native_distro()
    require_native_host_preconditions()
    payloads, receipt = stage._authenticated_payloads(
        assets, commit=commit, archive_sha256=archive_sha256, system=None,
    )
    _place_worker_files(Path("/"), payloads, receipt,
                        unit_paths=_systemd_unit_paths(), prepare_namespace=True)
    return {**receipt, "status": "AUTHENTICATED_WORKER_FILES_PLACED"}


_PROPOSAL_STAGE = ".admin-candidate-v2.stage"


def _initial_proposal(raw: bytes, decision_sha256: str) -> bytes:
    """Prepare generation one as data for separate review and locked intake."""
    if type(decision_sha256) is not str or not signatures.HEX64.fullmatch(decision_sha256):
        _reject("DECISION_DIGEST_INVALID")
    document = parse_install_bytes(raw, for_apply=True)
    if document["expected_state_generation"] != 0:
        _reject("INITIAL_GENERATION_REQUIRED")
    identified = [row for row in document["repositories"] if "id" in row]
    base = {**document, "repositories": identified}
    reserved = {row["id"] for row in identified}
    for row in document["repositories"]:
        if "id" not in row:
            suggestion = propose_automatic_repository_id(
                base, row, current_generation=0, reserved_ids=reserved,
            )
            row["id"] = suggestion["repository_id"]
            reserved.add(row["id"])
            identified.append(row)
    return _encode_proposal(document, decision_sha256)


def _encode_proposal(document: dict, decision_sha256: str, previous: dict | None = None) -> bytes:
    generation = document["expected_state_generation"]
    document["expected_state_generation"] = generation + 1
    configuration = _canonical(document, limit=MAX_DOCUMENT_BYTES)
    records = [{
        "id": row["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(row).encode("utf-8")
        ).hexdigest(),
        "desired_state": row["desired_state"],
        "observed_state": "not-activated",
    } for row in document["repositories"]]
    digest = hashlib.sha256(configuration).hexdigest()
    reservations = [{
        "id": row["id"],
        "canonical_identity_sha256": row["canonical_identity_sha256"],
        "status": "allocated",
    } for row in records]
    if previous is not None:
        present = {row["id"] for row in records}
        reservations.extend({
            **row, "status": "retired",
        } for row in previous["id_reservations"] if row["id"] not in present)
    snapshot = {
        "state_schema_version": 2,
        "state_generation": generation + 1,
        "configuration_base64": base64.b64encode(configuration).decode("ascii"),
        "configuration_sha256": digest,
        "repository_records": records,
        "id_reservations": reservations,
        "approval_reference": {
            "source": "operator",
            "decision_sha256": decision_sha256,
            "configuration_sha256": digest,
            "expected_generation": generation,
        },
    }
    preview_proposed_v2_state_transition(
        snapshot, expected_generation=generation, previous_snapshot=previous,
    )
    return _canonical(snapshot, limit=_MAX_STATE)


def _repair_proposal(raw: bytes, prior_raw: bytes, prior_sha256: str, decision_sha256: str) -> bytes:
    """Plan a partial same-version repair, preserving all omitted repositories."""
    if (type(prior_sha256) is not str or not signatures.HEX64.fullmatch(prior_sha256)
            or hashlib.sha256(prior_raw).hexdigest() != prior_sha256):
        _reject("PREVIOUS_STATE_PIN_MISMATCH")
    if type(decision_sha256) is not str or not signatures.HEX64.fullmatch(decision_sha256):
        _reject("DECISION_DIGEST_INVALID")
    previous = _canonical_json(prior_raw, _MAX_STATE)
    generation = _validate_proposed_v2_snapshot(previous)["generation"]
    current = parse_install_bytes(base64.b64decode(previous["configuration_base64"]), for_apply=True)
    proposed = parse_install_bytes(raw, for_apply=True)
    plan = plan_declarative_reconciliation(
        current, proposed, current_generation=generation,
    )
    if not plan["changed"]:
        return prior_raw
    return _encode_proposal(plan["candidate_document"], decision_sha256, previous)


def prepare_authenticated_proposal(
    assets: Path, document: Path, output: Path, *,
    commit: str, archive_sha256: str, decision_sha256: str,
    previous: Path | None = None, previous_sha256: str | None = None,
) -> dict:
    """Authenticate the candidate, then create a private proposal for review."""
    stage._authenticated_payloads(
        assets, commit=commit, archive_sha256=archive_sha256, system=None,
    )
    with ExitStack() as stack:
        source = os.open(document.parent, stage._DIRECTORY)
        stack.callback(os.close, source)
        raw = stage._asset_bytes(source, document.name, MAX_DOCUMENT_BYTES)
        if previous is None:
            if previous_sha256 is not None:
                _reject("PREVIOUS_STATE_REQUIRED")
            proposal = _initial_proposal(raw, decision_sha256)
        else:
            prior_source = os.open(previous.parent, stage._DIRECTORY)
            stack.callback(os.close, prior_source)
            prior_raw = stage._asset_bytes(prior_source, previous.name, _MAX_STATE)
            proposal = _repair_proposal(raw, prior_raw, previous_sha256, decision_sha256)
        destination = os.open(output.parent, stage._DIRECTORY)
        stack.callback(os.close, destination)
        parent = os.fstat(destination)
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            _reject("PROPOSAL_OUTPUT_UNSAFE")
        stage._write(destination, output.name, proposal, 0o600)
        os.fsync(destination)
    return {
        "status": "AUTHENTICATED_V2_PROPOSAL_PREPARED",
        "proposed_state_sha256": hashlib.sha256(proposal).hexdigest(),
        "state_generation": _canonical_json(proposal, _MAX_STATE)["state_generation"],
        "expected_state_sha256": previous_sha256,
        "requires_operator_review": True,
        "authorizes_service_activation": False,
    }


def _read_proposal_at(state: int, name: str) -> bytes | None:
    if _named(state, name) is None:
        return None
    return stage._asset_bytes(state, name, _MAX_ENVELOPE, installed_mode=0o600)


def _stage_proposal_under_root(
    root_fd: int, raw: bytes, reviewed_sha: str, *, expected_state_sha256: str | None = None,
) -> dict:
    if not signatures.HEX64.fullmatch(reviewed_sha) or hashlib.sha256(raw).hexdigest() != reviewed_sha:
        _reject("PROPOSAL_PIN_MISMATCH")
    snapshot = _canonical_json(raw, _MAX_STATE)
    if expected_state_sha256 is not None and (
        type(expected_state_sha256) is not str or not signatures.HEX64.fullmatch(expected_state_sha256)
    ):
        _reject("PREVIOUS_STATE_PIN_MISMATCH")
    with _locked(root_fd, 0) as state:
        # Native package-effects markers and all unresolved WALs must stay
        # in place. Proposal staging grants no recovery or activation authority.
        _no_conflicting_pending(state)
        previous, previous_raw = _read_v2(state, 0)
        generation = 0 if previous is None else previous["state_generation"]
        prior = _read_proposal_at(state, _PROPOSAL)
        interrupted = _read_proposal_at(state, _PROPOSAL_STAGE)
        if raw == previous_raw:
            if prior is None:
                _reject("COMMITTED_PROPOSAL_MISSING")
            prior_report, prior_state = _proposal(prior)
            if prior_state != raw or prior_report["expected_generation"] != generation - 1:
                _reject("COMMITTED_PROPOSAL_MISSING")
            if expected_state_sha256 is not None and expected_state_sha256 not in (
                reviewed_sha, prior_report["expected_state_sha256"],
            ):
                _reject("PREVIOUS_STATE_PIN_MISMATCH")
            if interrupted is not None:
                _reject("PROPOSAL_STAGE_PENDING")
            return {
                "status": "AUTHENTICATED_V2_PROPOSAL_ALREADY_COMMITTED",
                "proposed_state_sha256": reviewed_sha,
                "committed_generation": generation,
                "authorizes_service_activation": False,
            }
        if expected_state_sha256 is not None and (
            previous_raw is None or hashlib.sha256(previous_raw).hexdigest() != expected_state_sha256
        ):
            _reject("PREVIOUS_STATE_PIN_MISMATCH")
        preview_proposed_v2_state_transition(
            snapshot, expected_generation=generation, previous_snapshot=previous,
        )
        envelope = _canonical({
            "request_schema_version": 1,
            "expected_generation": generation,
            "expected_state_sha256": (
                None if previous_raw is None else hashlib.sha256(previous_raw).hexdigest()
            ),
            "next_state_base64": base64.b64encode(raw).decode("ascii"),
            "next_state_sha256": reviewed_sha,
        }, limit=_MAX_ENVELOPE)
        _proposal(envelope)
        if interrupted is not None and interrupted != envelope:
            _reject("FOREIGN_PROPOSAL_STAGE")
        if prior is not None and prior != envelope:
            # Replace only a proposal whose exact state is now committed.
            # A different, still-pending operator decision remains untouched.
            _, prior_state = _proposal(prior)
            if prior_state != previous_raw:
                _reject("UNCOMMITTED_PRIOR_PROPOSAL")
        if interrupted is not None:
            _unlink_known(state, _PROPOSAL_STAGE, envelope, 0, _MAX_ENVELOPE)
        if prior != envelope:
            _write_private(state, _PROPOSAL, _PROPOSAL_STAGE, prior, envelope, _MAX_ENVELOPE)
    return {
        "status": "AUTHENTICATED_V2_PROPOSAL_STAGED",
        "proposed_state_sha256": reviewed_sha,
        "expected_generation": generation,
        "authorizes_service_activation": False,
    }


def stage_authenticated_proposal(
    assets: Path, snapshot: Path, *, commit: str, archive_sha256: str, proposal_sha256: str,
    expected_state_sha256: str | None = None,
) -> dict:
    """Verify the installed worker against the authenticated release before staging."""
    _native_distro()
    require_native_host_preconditions()
    stage.verify_installed_worker(assets, commit=commit, archive_sha256=archive_sha256)
    with ExitStack() as stack:
        source = os.open(snapshot.parent, stage._DIRECTORY)
        stack.callback(os.close, source)
        raw = stage._asset_bytes(source, snapshot.name, _MAX_STATE)
        root = os.open("/", stage._DIRECTORY)
        stack.callback(os.close, root)
        return _stage_proposal_under_root(
            root, raw, proposal_sha256, expected_state_sha256=expected_state_sha256,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--archive-sha256", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--stage-v2-proposal", type=Path)
    mode.add_argument("--prepare-initial-v2-proposal", type=Path)
    mode.add_argument("--prepare-v2-repair", type=Path)
    parser.add_argument("--proposal-sha256")
    parser.add_argument("--proposal-output", type=Path)
    parser.add_argument("--decision-sha256")
    parser.add_argument("--previous-v2-state", type=Path)
    parser.add_argument("--previous-state-sha256")
    parser.add_argument("--expected-state-sha256")
    args = parser.parse_args()
    if (args.stage_v2_proposal is None) != (args.proposal_sha256 is None):
        parser.error("--stage-v2-proposal and --proposal-sha256 must be supplied together")
    repairing = args.prepare_v2_repair is not None
    preparing = args.prepare_initial_v2_proposal is not None or repairing
    if preparing != (args.proposal_output is not None) or preparing != (args.decision_sha256 is not None):
        parser.error("proposal preparation requires --proposal-output and --decision-sha256")
    if repairing != (args.previous_v2_state is not None) or repairing != (args.previous_state_sha256 is not None):
        parser.error("--prepare-v2-repair requires --previous-v2-state and --previous-state-sha256")
    if args.expected_state_sha256 is not None and args.stage_v2_proposal is None:
        parser.error("--expected-state-sha256 requires --stage-v2-proposal")
    pins = {"commit": args.commit, "archive_sha256": args.archive_sha256}
    try:
        if preparing:
            result = prepare_authenticated_proposal(
                args.assets, args.prepare_v2_repair or args.prepare_initial_v2_proposal,
                args.proposal_output, decision_sha256=args.decision_sha256,
                previous=args.previous_v2_state, previous_sha256=args.previous_state_sha256, **pins,
            )
        elif args.stage_v2_proposal is None:
            result = install_authenticated_worker(args.assets, **pins)
        else:
            result = stage_authenticated_proposal(
                args.assets, args.stage_v2_proposal, proposal_sha256=args.proposal_sha256,
                expected_state_sha256=args.expected_state_sha256, **pins,
            )
    except (OSError, ValueError, subprocess.SubprocessError,
            signatures.SignatureError, upgrade.UpgradeError):
        refused = "AUTHENTICATED_WORKER_PLACEMENT_REFUSED"
        if preparing or args.stage_v2_proposal is not None:
            refused = "AUTHENTICATED_V2_PROPOSAL_REFUSED"
        result = {"status": refused}
        status = 1
    else:
        status = 0
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
