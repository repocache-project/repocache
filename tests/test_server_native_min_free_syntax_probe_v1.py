"""Fail-closed security and report-contract tests for packaged nginx syntax."""
from __future__ import annotations
from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest import mock

import repocache.server_native_min_free_syntax_probe_v1 as p


class DisposableMinFreeProbeTests(unittest.TestCase):
    def test_exact_single_directive_change(self):
        root = Path("/tmp/repocache-minfree-fixture")
        a = p._config(root, min_free=False)
        b = p._config(root, min_free=True)
        self.assertEqual(b, a.replace(b"max_size=4m use_temp_path",
                                      b"max_size=4m min_free=1m use_temp_path"))
        self.assertIn(b"proxy_cache_path ", b)
        self.assertNotIn(b"include ", b)

    def test_unsafe_paths_and_untyped_flag_rejected(self):
        for root in (Path("/etc/nginx"), Path("/tmp/x"), Path("/tmp/repocache-minfree-x/y"),
                     Path("/tmp/repocache-minfree-unsafe;directive")):
            with self.subTest(root=root), self.assertRaises(p.NativeMinFreeProbeError):
                p._config(root, min_free=True)
        for val in (1, None, "true"):
            with self.subTest(val=val), self.assertRaises(p.NativeMinFreeProbeError):
                p._config(Path("/tmp/repocache-minfree-fixture"), min_free=val)

    def test_supported_distribution_identities(self):
        examples = (('ID=debian\nVERSION_ID="13"\n', "debian13"),
                    ('ID="almalinux"\nVERSION_ID=10\n', "almalinux10"),
                    ('ID=almalinux\nVERSION_ID="10.0"\n', "almalinux10"),
                    ('ID=almalinux\nVERSION_ID="10.1"\n', "almalinux10"))
        for raw, expected in examples:
            with self.subTest(expected=expected), mock.patch.object(
                Path, "read_text", return_value=raw,
            ):
                self.assertEqual(p._read_os_platform(), expected)

    def test_foreign_duplicate_and_malformed_identity_rejected(self):
        cases = ('ID=ubuntu\nVERSION_ID=24.04\n',
                 'ID=debian\nVERSION_ID=12\n',
                 'ID=almalinux\nVERSION_ID=9\n',
                 'ID=almalinux\nVERSION_ID=100\n',
                 'ID=almalinux\nVERSION_ID=10.0.1\n',
                 'ID=debian\nID=debian\nVERSION_ID=13\n',
                 'ID=debian\nVERSION_ID=13\nVERSION_ID=13\n',
                 'ID=debian\nVERSION_ID="13";unsafe\n',
                 'VERSION_ID=13\n')
        for raw in cases:
            with self.subTest(raw=raw), mock.patch.object(
                Path, "read_text", return_value=raw,
            ), self.assertRaises(p.NativeMinFreeProbeError):
                p._read_os_platform()

    def test_identity_io_failure_refused(self):
        with mock.patch.object(Path, "read_text", side_effect=OSError):
            with self.assertRaisesRegex(p.NativeMinFreeProbeError, "IDENTITY_UNVERIFIED"):
                p._read_os_platform()

    def test_nginx_t_fixed_subprocess_no_shell(self):
        with mock.patch.object(p.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertTrue(p._run_syntax("/usr/sbin/nginx",
                Path("/tmp/repocache-minfree-x"), Path("/tmp/repocache-minfree-x/nginx.conf")))
        args, kw = run.call_args
        self.assertEqual(args[0], ["/usr/sbin/nginx", "-t", "-p", "/tmp/repocache-minfree-x",
                                   "-c", "/tmp/repocache-minfree-x/nginx.conf"])
        self.assertEqual(kw["stdin"], subprocess.DEVNULL)
        self.assertEqual(kw["stdout"], subprocess.DEVNULL)
        self.assertEqual(kw["stderr"], subprocess.DEVNULL)
        self.assertIs(kw["check"], False)
        self.assertLessEqual(kw["timeout"], 12)
        self.assertNotIn("shell", kw)

    def test_syntax_rejection_is_bounded_false(self):
        with mock.patch.object(p.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
            self.assertFalse(p._run_syntax("/usr/sbin/nginx",
                Path("/tmp/repocache-minfree-x"), Path("/tmp/repocache-minfree-x/nginx.conf")))

    def test_timeout_and_binary_substitution_refused(self):
        with mock.patch.object(p.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired(["nginx"], 12)):
            with self.assertRaisesRegex(p.NativeMinFreeProbeError, "EXECUTION_UNVERIFIED"):
                p._run_syntax("/usr/sbin/nginx", Path("/tmp/repocache-minfree-x"),
                              Path("/tmp/repocache-minfree-x/nginx.conf"))
        for binary in ("/bin/sh", "nginx", "/tmp/nginx", "/usr/sbin/nginx -s reload", None):
            with self.subTest(binary=binary), self.assertRaises(p.NativeMinFreeProbeError):
                p._run_syntax(binary, Path("/tmp/repocache-minfree-x"),
                              Path("/tmp/repocache-minfree-x/nginx.conf"))

    def test_baseline_failure_not_conflated_with_unsupported(self):
        with self.assertRaisesRegex(p.NativeMinFreeProbeError, "BASELINE_SYNTAX_UNVERIFIED"):
            p._observed("debian13", False, False)

    def test_both_feature_outcomes_non_authorizing(self):
        for distro in ("debian13", "almalinux10"):
            for accepted in (True, False):
                with self.subTest(distro=distro, accepted=accepted):
                    result = p._observed(distro, True, accepted)
                    self.assertEqual(result["native_min_free_syntax_accepted"], accepted)
                    for field in (
                        "native_package_signature_verified",
                        "installed_host_nginx_identity_verified",
                        "native_min_free_supported_on_host_verified",
                        "selinux_enforcing_verified", "operator_approval_verified",
                        "authorizes_enable_min_free_on_host",
                        "authorizes_nginx_reload", "authorizes_cache_mutation",
                        "authorizes_firewall_change",
                    ):
                        self.assertIs(result[field], False, field)

    def test_untrusted_observation_fields_refused(self):
        for args in (("foreign", True, True), ("debian13", 1, True),
                     ("debian13", True, 1)):
            with self.subTest(args=args), self.assertRaises(p.NativeMinFreeProbeError):
                p._observed(*args)

    def test_root_or_not_marked_does_not_call_nginx(self):
        for uid, flag, marker in ((0, "1", True), (65534, "", True),
                                  (65534, "1", False)):
            with self.subTest(uid=uid, flag=flag, marker=marker), mock.patch.object(
                p.os, "geteuid", return_value=uid,
            ), mock.patch.dict(os.environ, {p._RUNTIME_ENV: flag}), mock.patch.object(
                Path, "is_file", return_value=marker,
            ), mock.patch.object(p.shutil, "which") as binary:
                with self.assertRaisesRegex(p.NativeMinFreeProbeError, "DISPOSABLE_NONROOT_REQUIRED"):
                    p.probe_disposable_native_min_free()
                binary.assert_not_called()

    def test_probes_baseline_first_and_keeps_negative_outcome(self):
        with mock.patch.object(p.os, "geteuid", return_value=65534), mock.patch.dict(
            os.environ, {p._RUNTIME_ENV: "1"},
        ), mock.patch.object(Path, "is_file", return_value=True), mock.patch.object(
            p, "_read_os_platform", return_value="debian13",
        ), mock.patch.object(p.shutil, "which", return_value="/usr/sbin/nginx"), mock.patch.object(
            p, "_run_syntax", side_effect=[True, False],
        ) as run:
            result = p.probe_disposable_native_min_free()
        self.assertEqual(result["status"], "MIN_FREE_DISPOSABLE_SYNTAX_NOT_ACCEPTED")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[1],
                         run.call_args_list[1].args[1])

    def test_bad_baseline_never_probes_optional_feature(self):
        with mock.patch.object(p.os, "geteuid", return_value=65534), mock.patch.dict(
            os.environ, {p._RUNTIME_ENV: "1"},
        ), mock.patch.object(Path, "is_file", return_value=True), mock.patch.object(
            p, "_read_os_platform", return_value="almalinux10",
        ), mock.patch.object(p.shutil, "which", return_value="/usr/sbin/nginx"), mock.patch.object(
            p, "_run_syntax", return_value=False,
        ) as run:
            with self.assertRaisesRegex(p.NativeMinFreeProbeError, "BASELINE_SYNTAX_UNVERIFIED"):
                p.probe_disposable_native_min_free()
        self.assertEqual(run.call_count, 1)

    def test_json_stdout_is_redacted(self):
        with mock.patch.object(p, "probe_disposable_native_min_free",
                               return_value=p._observed("debian13", True, True)):
            capture = StringIO()
            with redirect_stdout(capture):
                self.assertEqual(p.main(), 0)
            report = json.loads(capture.getvalue())
            self.assertTrue(report["native_min_free_syntax_accepted"])
            self.assertFalse(report["authorizes_nginx_reload"])
            self.assertEqual(len(capture.getvalue().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
