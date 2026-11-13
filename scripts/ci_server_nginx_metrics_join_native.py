#!/usr/bin/env python3
"""Run combined route/metrics candidate through stock Linux nginx -t."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from repocache.server_nginx_metrics_bundle_join_v1 import (
    render_repository_nginx_metrics_join,
)


def main():
    if not (Path("/.dockerenv").is_file() and os.geteuid() != 0
            and os.getenv("REPOCACHE_DISPOSABLE_NGINX_SMOKE") == "1"):
        raise AssertionError("DISPOSABLE_NONROOT_ONLY")
    nginx=shutil.which("nginx")
    assert nginx
    source=Path("/repo/docs/examples/server-install-v1.json")
    doc=json.loads(source.read_text())
    doc["deployment"]["logging"]["metrics_opt_in"]=True
    doc["repositories"][0]["desired_state"]="active"
    doc["repositories"][1]["desired_state"]="active"
    doc["repositories"][1]["id"]="almalinux-baseos"
    ca=next(p for p in ("/etc/ssl/certs/ca-certificates.crt",
                        "/etc/pki/tls/certs/ca-bundle.crt") if Path(p).is_file())
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        for name in ("client_body","proxy","fastcgi","uwsgi","scgi"):
            (root/name).mkdir()
        cache=root/"cache"
        doc["deployment"]["paths"]["cache_root"]=str(cache)
        for repo in doc["repositories"]:
            (cache/repo["id"]).mkdir(parents=True)
        pins={r["id"]:{"mirror.example.invalid":["8.8.8.8"]}
              for r in doc["repositories"]}
        merged=render_repository_nginx_metrics_join(
            doc,expected_state_generation=0,
            candidate_pins_by_repository=pins,ca_bundle_path=ca)
        assert merged["server_fragment"].count("access_log ") == 2
        http=merged["http_fragment"].replace(
            "/var/log/nginx/repocache-managed/metrics.jsonl",str(root/"metrics.jsonl"))
        server=merged["server_fragment"].replace(
            "/var/log/nginx/repocache-managed/metrics.jsonl",str(root/"metrics.jsonl"))
        config=(f"pid {root/'nginx.pid'};\n"
                f"error_log {root/'error.log'} notice;\n"
                "worker_processes 1;\nevents { worker_connections 64; }\n"
                "http {\naccess_log off;\n"
                + "".join(f"{n}_temp_path {root/n};\n" for n in
                          ("client_body","proxy","fastcgi","uwsgi","scgi"))
                + http + "\nserver { listen 127.0.0.1:19617;\n"
                + server + "\n}\n}\n")
        (root/"nginx.conf").write_text(config)
        result=subprocess.run([nginx,"-t","-p",str(root),
                               "-c",str(root/"nginx.conf")],
                              capture_output=True,timeout=15,check=False)
        assert result.returncode == 0, "STOCK_NGINX_COMPOSITE_INVALID"
        assert not merged["authorizes_nginx_activation"]
        print("PASS: actual stock NGINX validates joined approved routes and metrics")
if __name__ == "__main__":
    main()
