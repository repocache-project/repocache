"""Security boundary and fixed NGINX min_free configuration tests."""
from pathlib import Path
import unittest
import importlib.util


class ConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "scripts/ci_nginx_min_free_reclaim_v1.py"
        spec = importlib.util.spec_from_file_location("native_minfree_lab", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_baseline_and_pressure_differ_only_in_min_free_value(self):
        root = Path("/tmp/repocache-minfree-fixture")
        baseline = self.module.config(root, 12345, 12346, 1)
        pressure = self.module.config(root, 12345, 12346, 4096)
        self.assertEqual(pressure, baseline.replace("min_free=1m", "min_free=4096m"))
        self.assertIn("max_size=16m", pressure)
        self.assertIn("manager_files=100", pressure)
        self.assertIn("proxy_cache repocache_minfree", pressure)
        self.assertNotIn("include ", pressure)

    def test_invalid_watermark_refused(self):
        for invalid in (None, True, False, 0, -1, 2**40, "4;access_log"):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                self.module.config(Path("/tmp/private"), 12345, 12346, invalid)

    def test_scope_does_not_include_global_signal_or_host_delete(self):
        text = (
            Path(__file__).resolve().parents[1] /
            "scripts/ci_nginx_min_free_reclaim_v1.py"
        ).read_text(encoding="utf-8")
        self.assertIn("proc.send_signal(signal.SIGHUP)", text)
        self.assertIn("NONROOT_DISPOSABLE_CONTAINER_REQUIRED", text)
        for invalid in ("os.unlink(", "os.remove(", "os.chmod(",
                        "killall", "systemctl", "rm -rf", "apt-get", "dnf -y"):
            self.assertNotIn(invalid, text)


if __name__ == "__main__":
    unittest.main()
