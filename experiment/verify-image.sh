#!/usr/bin/env bash
set -Eeuo pipefail
# Check the exact vendor digest, never a digest supplied by the cache.
test -f "$BENCH_IMAGE" && test ! -L "$BENCH_IMAGE" || exit 1
case "$PR237_PLATFORM" in
  almalinux10)
    [[ "$PR237_IMAGE_SHA256" =~ ^[a-f0-9]{64}$ && -z "$PR237_IMAGE_SHA512" ]]
    printf '%s  %s\n' "$PR237_IMAGE_SHA256" "$BENCH_IMAGE" | sha256sum -c - ;;
  debian13)
    [[ "$PR237_IMAGE_SHA512" =~ ^[a-f0-9]{128}$ && -z "$PR237_IMAGE_SHA256" ]]
    printf '%s  %s\n' "$PR237_IMAGE_SHA512" "$BENCH_IMAGE" | sha512sum -c - ;;
  *) exit 2 ;;
esac
