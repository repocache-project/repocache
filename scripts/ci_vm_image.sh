#!/usr/bin/env bash
# Only pristine vendor image bytes are eligible for reuse; never guest state.
ci_vm_image_inputs() {
  case "${PR237_PLATFORM:-}" in
    debian13)
      [[ "${PR237_IMAGE_URL:-}" == https://cloud.debian.org/images/cloud/trixie/* &&
         "${PR237_IMAGE_SHA512:-}" =~ ^[a-f0-9]{128}$ && -z "${PR237_IMAGE_SHA256:-}" ]] ;;
    almalinux10)
      [[ "${PR237_IMAGE_URL:-}" == https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/* &&
         "${PR237_IMAGE_SHA256:-}" =~ ^[a-f0-9]{64}$ && -z "${PR237_IMAGE_SHA512:-}" ]] ;;
    *) return 1 ;;
  esac
}
ci_vm_image_verify() {
  local image="$1" actual expected
  ci_vm_image_inputs || return 1
  test -f "$image" && test ! -L "$image" || return 1
  if test "$PR237_PLATFORM" = debian13; then
    actual="$(sha512sum < "$image")" || return 1
    expected="$PR237_IMAGE_SHA512"
  else
    actual="$(sha256sum < "$image")" || return 1
    expected="$PR237_IMAGE_SHA256"
  fi
  test "${actual%% *}" = "$expected" || { echo 'Vendor image digest mismatch' >&2; return 1; }
}
ci_vm_image_acquire() {
  local dest="$1" cached="${2:-}" scratch parent
  ci_vm_image_inputs || { echo 'Invalid vendor image inputs' >&2; return 1; }
  parent="$(dirname -- "$dest")" || return 1
  test -d "$parent" && test ! -L "$parent" && test ! -e "$dest" && test ! -L "$dest" || return 1
  if test -n "$cached"; then
    parent="$(dirname -- "$cached")" || return 1
    test -d "$parent" && test ! -L "$parent" || return 1
  fi
  scratch="$(mktemp -- "${dest}.part.XXXXXXXX")" || return 1
  if test -n "$cached" && { test -e "$cached" || test -L "$cached"; }; then
    if ! { test -f "$cached" && test ! -L "$cached" && cp --reflink=auto -- "$cached" "$scratch"; }; then
      rm -f -- "$scratch"; return 1
    fi
    echo 'Image source: exact-digest cache (verification required)'
  else
    echo 'Image source: official vendor origin'
    if ! curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fL --retry 3 --retry-delay 5 --max-time 1200 -o "$scratch" "$PR237_IMAGE_URL"; then
      rm -f -- "$scratch"; return 1
    fi
  fi
  if ! { ci_vm_image_verify "$scratch" && chmod 0444 "$scratch" && mv -T -- "$scratch" "$dest"; }; then
    rm -f -- "$scratch"; return 1
  fi
  echo 'Vendor image digest verified'
}
