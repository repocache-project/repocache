#!/usr/bin/env python3
"""PR237 disposable VM: actual native APT/DNF install from a synthetic signed worker.

No real publisher signature, external trust anchor, daemon activation, or
package effects rollback is claimed. Entire root filesystem is a QEMU guest.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path("/root/pr237-synthetic-fixture")
STATE = Path("/var/lib/repocache/server")

def run(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv), capture_output=True, text=True, timeout=30, check=False,
        stdin=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )

def procfs_scan_diagnostic() -> str:
    """Mirror read-only kernel comm scan, output fixed failure classes only.

    Never log guest PIDs, names, command lines, credentials or /proc data.
    This function neither modifies production preflight nor supplies authority.
    """
    observed = 0
    try:
        with os.scandir("/proc") as entries:
            for entry in entries:
                name = entry.name
                if (not name.isascii() or not name.isdecimal()
                        or name.startswith("0") or len(name) > 10):
                    continue
                observed += 1
                if observed > 65536:
                    return "TOO_MANY_PIDS"
                try:
                    fd = os.open("/proc/" + name + "/comm",
                                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                                 | getattr(os, "O_CLOEXEC", 0))
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    return "COMM_OPEN_ERRNO_" + str(exc.errno)
                try:
                    try:
                        raw = os.read(fd, 64)
                        overflow = os.read(fd, 1)
                    except FileNotFoundError:
                        continue
                    except OSError as exc:
                        return "COMM_READ_ERRNO_" + str(exc.errno)
                    if not raw:
                        return "COMM_EMPTY"
                    if overflow:
                        return "COMM_SECOND_READ_NONEMPTY_FIRSTLEN_" + str(len(raw))
                    if len(raw) > 32:
                        return "COMM_TOO_LONG_LEN_" + str(len(raw))
                    value = raw.removesuffix(b"\\n")
                    if value == b"nginx" or value.startswith(b"nginx:"):
                        return "NGINX_PROCESS_PRESENT"
                finally:
                    os.close(fd)
        return "VALID_PROCESS_SCAN"
    except OSError as exc:
        return "PROC_SCAN_ERRNO_" + str(exc.errno)


def report(distribution: str) -> None:
    assert os.getresuid() == (0, 0, 0)
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert run("/usr/bin/systemd-detect-virt", "--vm").returncode == 0
    source = Path("/home/pr237ci/combined")
    sys.path[:0] = [str(source / "src"), str(source)]
    from scripts import install_native_root_worker, stage_native_root_worker
    from repocache.server_stock_nginx_package_owner_v1 import (
        inspect_stock_nginx_package_owner, inspect_stock_nginx_package_file_integrity,
    )
    from repocache.server_native_nginx_service_unit_v1 import inspect_native_nginx_unit
    from repocache.server_native_nginx_package_journal_v1 import (
        NATIVE_PENDING_NAME, NATIVE_COMPLETE_NAME,
    )

    pins = json.loads((ROOT / "pins.json").read_bytes())
    assert set(pins) == {"commit", "archive_sha256"}
    assets = ROOT / "assets"
    assert stage_native_root_worker.verify_installed_worker(assets, **pins)["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"

    def native_observation() -> None:
        assert inspect_stock_nginx_package_owner()["native_package_db_owner_observed"] is True
        assert inspect_stock_nginx_package_file_integrity()["native_package_file_integrity_verified"] is True
        assert inspect_native_nginx_unit(distribution).code == "VENDOR_NGINX_UNIT_OBSERVED"
        assert run("/usr/sbin/nginx", "-t").returncode == 0
        enabled = run("/usr/bin/systemctl", "is-enabled", "nginx.service")
        active = run("/usr/bin/systemctl", "is-active", "nginx.service")
        assert (enabled.returncode, enabled.stdout.strip()) == (1, "disabled"), (enabled.returncode, enabled.stdout.strip())
        assert (active.returncode, active.stdout.strip()) == (3, "inactive"), (active.returncode, active.stdout.strip())
        print("PASS: audited native NGINX package and vendor unit; systemd disabled/inactive")

    pending = STATE / NATIVE_PENDING_NAME
    complete = STATE / NATIVE_COMPLETE_NAME
    assert STATE.is_dir()
    assert (STATE / ".state-v1.lock").is_file()
    assert run("/usr/bin/systemctl", "is-active", "repocache-control.socket").returncode != 0
    if len(sys.argv) != 3:
        raise AssertionError("usage: native-package guest distribution install|after")
    phase = sys.argv[2]
    if phase == "install":
        assert not Path("/usr/sbin/nginx").exists()
        assert not Path("/etc/nginx").exists()
        assert not pending.exists() and not complete.exists()
        doc = ROOT / "reviewed-install.json"
        raw = (source / "docs/examples/server-install-v1.json").read_bytes()
        fd = os.open(doc, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        digest = hashlib.sha256(raw).hexdigest()
        # Invalid input MUST be rejected before native package manager effects.
        try:
            install_native_root_worker.install_authenticated_native_nginx(
                assets, doc, "0" * 64, **pins,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("Native package install accepted invalid document SHA")
        assert not Path("/usr/sbin/nginx").exists()
        assert not pending.exists() and not complete.exists()
        print("PASS: genuine installed-worker package entry refused tampered document pin before APT/DNF")

        # Print only fixed, redacted preflight codes from the REAL observers.
        # This does not bypass any native guard or modify host/package state.
        from repocache.server_install_v1 import parse_install_bytes
        from repocache.server_native_nginx_local_boundary_v1 import inspect_native_nginx_local_boundary
        from repocache.server_native_nginx_prepackage_state_v1 import (
            inspect_current_namespace_prepackage_state, PrepackageStateInspectionError,
        )
        from repocache.server_native_package_trust_v1 import _NATIVE, _trusted_key
        import sys as native_python
        boundary = inspect_native_nginx_local_boundary(
            os_release=Path("/usr/lib/os-release").read_text(encoding="ascii"),
            python_version=native_python.version_info[:2], document=parse_install_bytes(raw),
        )
        print("native_prepackage_code=" + boundary.code, flush=True)
        print("native_prepackage_footprint=" + boundary.footprint_code, flush=True)
        if boundary.footprint_code == "NGINX_PROCESS_SCAN_UNVERIFIED":
            from repocache.server_native_nginx_ownership_v1 import _scan_nginx_process_footprint
            for diagnostic_index in range(3):
                print("native_real_proc_probe_" + str(diagnostic_index) + "="
                      + _scan_nginx_process_footprint(), flush=True)
            print("native_first_proc_failure=" + procfs_scan_diagnostic(), flush=True)
        print("native_distro_signing_anchor_trusted=" + str(_trusted_key(_NATIVE[distribution][2])), flush=True)
        try:
            observed = inspect_current_namespace_prepackage_state()
            print("native_protected_state_code=" + observed["status"], flush=True)
        except PrepackageStateInspectionError as exc:
            print("native_protected_state_code=" + str(exc), flush=True)

        outcome = install_native_root_worker.install_authenticated_native_nginx(
            assets, doc, digest, **pins,
        )
        assert outcome["status"] == "AUTHENTICATED_NATIVE_NGINX_PACKAGE_INSTALLED"
        assert outcome["native_package_effects_reconciled"] is True
        assert outcome["authorizes_service_activation"] is False
        assert not pending.exists() and complete.is_file()
        info = complete.stat()
        assert info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600
        native_observation()
        cache_parent = Path("/var/cache/nginx")
        cache_info = cache_parent.lstat()
        assert stat.S_ISDIR(cache_info.st_mode)
        assert cache_info.st_uid == 0 and cache_info.st_gid == 0
        assert stat.S_IMODE(cache_info.st_mode) == 0o755
        assert not cache_parent.is_symlink()
        print("PASS: native installer provisioned exact owned nginx cache sandbox mount target before completion", flush=True)
        existing = complete.read_bytes()
        try:
            install_native_root_worker.install_authenticated_native_nginx(
                assets, doc, digest, **pins,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("Second fresh native install accepted instead of refusing")
        assert complete.read_bytes() == existing and not pending.exists()
        (ROOT / "native-completed-sha256.txt").write_text(hashlib.sha256(existing).hexdigest() + "\n")
        print("PASS: actual signed-source native APT/DNF NGINX package installer, durable completion receipt, duplicate refusal")
        print("native_completed_sha256=" + hashlib.sha256(existing).hexdigest())
    elif phase == "after":
        assert not pending.exists() and complete.is_file()
        original = (ROOT / "native-completed-sha256.txt").read_text().strip()
        assert len(original) == 64
        assert hashlib.sha256(complete.read_bytes()).hexdigest() == original
        native_observation()
        cache_info = Path("/var/cache/nginx").lstat()
        assert stat.S_ISDIR(cache_info.st_mode)
        assert (cache_info.st_uid, cache_info.st_gid, stat.S_IMODE(cache_info.st_mode)) == (0, 0, 0o755)
        assert stage_native_root_worker.verify_installed_worker(assets, **pins)["status"] == "AUTHENTICATED_WORKER_FILES_MATCH"
        for name in ("repocache-control.socket", "repocache-control.service"):
            assert run("/usr/bin/systemctl", "is-active", name).returncode != 0
        print("PASS: actual native APT/DNF completion persisted across kernel reboot; no NGINX or REPOCACHE autostart")

        # Move one step closer to a genuine installed v2 lifecycle without
        # applying any candidate, starting the fixed control socket, or
        # granting production operator authorization.
        proposal = ROOT / "reviewed-initial-v2.json"
        prepared = install_native_root_worker.prepare_authenticated_proposal(
            assets, ROOT / "reviewed-install.json", proposal,
            decision_sha256="d" * 64, **pins,
        )
        assert prepared["status"] == "AUTHENTICATED_V2_PROPOSAL_PREPARED"
        assert prepared["state_generation"] == 1
        assert prepared["requires_operator_review"] is True
        assert prepared["authorizes_service_activation"] is False
        proposal_raw = proposal.read_bytes()
        proposed_sha = hashlib.sha256(proposal_raw).hexdigest()
        assert prepared["proposed_state_sha256"] == proposed_sha
        pending_proposal = STATE / ".admin-candidate-v2.json"
        assert not pending_proposal.exists()
        assert not (STATE / "state-v2.json").exists()
        try:
            install_native_root_worker.stage_authenticated_proposal(
                assets, proposal, proposal_sha256="0" * 64, **pins,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("Unreviewed/mismatching proposed v2 SHA was accepted")
        assert not pending_proposal.exists() and not (STATE / "state-v2.json").exists()
        print("PASS: actual native signed-fixture proposal staging refuses an incorrect reviewed digest")

        staged = install_native_root_worker.stage_authenticated_proposal(
            assets, proposal, proposal_sha256=proposed_sha, **pins,
        )
        assert staged == {
            "status": "AUTHENTICATED_V2_PROPOSAL_STAGED",
            "proposed_state_sha256": proposed_sha,
            "expected_generation": 0,
            "authorizes_service_activation": False,
        }
        envelope_before = pending_proposal.read_bytes()
        info_before = pending_proposal.stat()
        repeated = install_native_root_worker.stage_authenticated_proposal(
            assets, proposal, proposal_sha256=proposed_sha, **pins,
        )
        assert repeated == staged
        info_after = pending_proposal.stat()
        assert pending_proposal.read_bytes() == envelope_before
        assert (info_before.st_ino, info_before.st_mtime_ns) == (
            info_after.st_ino, info_after.st_mtime_ns
        )
        assert not (STATE / "state-v2.json").exists()
        assert not (STATE / ".state-v2-native.pending").exists()
        assert hashlib.sha256(complete.read_bytes()).hexdigest() == original
        for name in ("nginx.service", "repocache-control.service", "repocache-control.socket"):
            assert run("/usr/bin/systemctl", "is-active", name).returncode != 0
        # Exercise the REAL root-owned completed-receipt parser against the
        # fixed installed namespace after reboot, not a mocked JSON fixture.
        # A corrupted package audit must never be promoted to trust.
        from repocache.server_protected_state_store_v1 import _locked
        from repocache.server_native_nginx_package_journal_v1 import (
            _read_completed_native_install_under_lock, NativePackageJournalError,
        )
        from repocache.server_native_v2_transaction_v1 import (
            _require_audited_native_package_for_activation, NativeV2TransactionError,
        )
        rootfd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            with _locked(rootfd, 0) as directory:
                validated = _read_completed_native_install_under_lock(
                    directory, owner_uid=0, distribution=distribution,
                )
                assert validated is not None
                assert validated["native_package_file_integrity_verified"] is True
                assert validated["booted_native_service_verified"] is False
                assert validated["publisher_artifact_verified"] is False
                _require_audited_native_package_for_activation(
                    directory, distribution=distribution,
                )
        finally:
            os.close(rootfd)
        original_receipt = complete.read_bytes()
        initial_receipt_stat = complete.stat()
        original_proposal = pending_proposal.read_bytes()
        original_proposal_stat = pending_proposal.stat()
        try:
            # Keep ownership/mode/inode unchanged, alter only semantic bytes.
            altered = original_receipt.replace(
                b'"native_package_file_integrity_verified":true',
                b'"native_package_file_integrity_verified":false', 1,
            )
            assert altered != original_receipt
            complete.write_bytes(altered)
            rootfd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                with _locked(rootfd, 0) as directory:
                    try:
                        _read_completed_native_install_under_lock(
                            directory, owner_uid=0, distribution=distribution,
                        )
                    except NativePackageJournalError as error:
                        assert str(error) == "NATIVE_COMPLETION_RECEIPT_INVALID"
                    else:
                        raise AssertionError("Corrupted real native completion receipt accepted")
                    try:
                        _require_audited_native_package_for_activation(
                            directory, distribution=distribution,
                        )
                    except (NativeV2TransactionError, NativePackageJournalError) as error:
                        # The legacy-state gate checks the same protected
                        # receipt before the activation gate catches it. Both
                        # are fail-closed, and neither may mutate any resource.
                        assert str(error) in (
                            "NATIVE_COMPLETION_RECEIPT_INVALID",
                            "NATIVE_V2_NATIVE_PACKAGE_PROVENANCE_UNVERIFIED",
                        )
                    else:
                        raise AssertionError("Real native APPLY/RELOAD audit gate accepted a corrupted package receipt")
            finally:
                os.close(rootfd)
            assert pending_proposal.read_bytes() == original_proposal
            assert not (STATE / "state-v2.json").exists()
            assert not (STATE / ".state-v2-native.pending").exists()
        finally:
            complete.write_bytes(original_receipt)
        restored_receipt_stat = complete.stat()
        assert (restored_receipt_stat.st_ino, restored_receipt_stat.st_uid,
                restored_receipt_stat.st_gid, stat.S_IMODE(restored_receipt_stat.st_mode)) == (
                    initial_receipt_stat.st_ino, 0, 0, 0o600
                )
        assert pending_proposal.read_bytes() == original_proposal
        assert pending_proposal.stat().st_ino == original_proposal_stat.st_ino
        assert hashlib.sha256(complete.read_bytes()).hexdigest() == original
        rootfd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            with _locked(rootfd, 0) as directory:
                assert _read_completed_native_install_under_lock(
                    directory, owner_uid=0, distribution=distribution,
                ) is not None
                _require_audited_native_package_for_activation(
                    directory, distribution=distribution,
                )
        finally:
            os.close(rootfd)
        native_observation()
        print("PASS: real post-reboot completed-package receipt corruption rejected under protected lock; existing staged proposal and service preserved")
        print("PASS: actual signed-fixture reviewed v2 proposal staged idempotently on booted host, without state commit or service activation")
        print("NOT VERIFIED: actual package-manager interruption recovery, publisher release signing, v2 activation")
    else:
        raise ValueError("Invalid phase")

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("debian", "almalinux"):
        raise SystemExit("Usage: synthetic-native-package.py debian|almalinux install|after")
    report(sys.argv[1])
