#!/usr/bin/env bash
# Run ONLY as root within a booted, disposable QEMU guest.
set -Eeuo pipefail
platform="$1"
phase="$2"
test "$(id -u)" = 0
test "$(cat /proc/1/comm)" = systemd
test "$(uname -m)" = x86_64
. /etc/os-release
case "$platform" in
  debian13) test "$ID" = debian; test "$VERSION_ID" = 13; manager=apt ;;
  almalinux10)
    test "$ID" = almalinux
    case "$VERSION_ID" in 10*) ;; *) exit 1;; esac
    manager=dnf
    command -v getenforce
    test "$(getenforce)" = Enforcing
    sestatus || true
    ;;
  *) exit 2;;
esac
echo "PASS: actual OS=$ID version=$VERSION_ID kernel=$(uname -r) PID1=$(cat /proc/1/comm) manager=$manager"
if test "$platform" = almalinux10; then echo 'PASS: kernel SELinux enforcing'; fi
case "$phase" in
  prepare)
    if test "$platform" = debian13; then
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends python3-cryptography python3-pytest openssl curl
    else
      dnf -y -q install python3-cryptography python3-pytest openssl curl
    fi
    cd /home/pr237ci/source
    export PYTHONPATH=/home/pr237ci/source/src
    python3 -B scripts/ci_v06_root_worker_target_guard.py "$(test "$platform" = debian13 && echo debian || echo almalinux)"
    echo 'PASS: real native worker target identity guard (not installed worker)'
    test ! -e /usr/sbin/nginx
    systemctl mask nginx.service
    if test "$platform" = debian13; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends nginx
    else
      dnf -y -q install nginx
    fi
    nginx -t
    test "$(systemctl is-enabled nginx.service)" = masked
    ! systemctl is-active --quiet nginx.service
    echo 'PASS: stock APT/DNF NGINX installed, masked and inactive'
    ;;
  after)
    test "$(systemctl is-enabled nginx.service)" = masked
    ! systemctl is-active --quiet nginx.service
    echo 'PASS: persistent NGINX mask survived kernel reboot'
    systemctl unmask nginx.service
    systemctl disable nginx.service || true
    systemctl daemon-reload
    nginx -t
    systemctl start nginx.service
    systemctl is-active --quiet nginx.service
    curl -fsS --max-time 10 http://127.0.0.1/ >/dev/null
    echo 'PASS: real NGINX service activation and local HTTP'
    python3 -B /home/pr237ci/source/scripts/ci_pr237_native_host_integration.py "$(test "$platform" = debian13 && echo debian || echo almalinux)"
    systemctl stop nginx.service
    systemctl disable nginx.service || true
    ! systemctl is-active --quiet nginx.service
    test "$(systemctl is-enabled nginx.service)" = disabled
    echo 'PASS: NGINX stopped, disabled, autostart blocked'
    export PYTHONPATH=/home/pr237ci/source/src
    cd /home/pr237ci/source
    python3 -m pytest -q tests/test_server_native_nginx_package_journal_v1.py tests/test_server_stock_nginx_package_owner_v1.py
    echo 'PASS: existing journal/package-owner fixture tests executed in native guest'
    ;;
  journal-prepare)
    python3 -B /home/pr237ci/source/scripts/ci_pr237_native_journal_reboot.py "$(test "$platform" = debian13 && echo debian || echo almalinux)" prepare
    ;;
  journal-after)
    python3 -B /home/pr237ci/source/scripts/ci_pr237_native_journal_reboot.py "$(test "$platform" = debian13 && echo debian || echo almalinux)" after
    ;;
  *) exit 2 ;;
esac
