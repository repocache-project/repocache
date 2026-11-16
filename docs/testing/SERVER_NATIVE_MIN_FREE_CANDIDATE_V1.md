# Native NGINX min_free candidate emission — v0.6.0 / #97

The existing v1 repository-centric candidate renderer already emits each
repository's independent proxy_cache_path with inherited and overridden
inactive and max_size policy. It previously had no way to emit the optional
stock NGINX min_free argument from the validated global critical disk-free
threshold, even when the native binary supported the directive.

The optional, strictly boolean native_min_free_supported argument now emits
" min_free=<critical_free_bytes>" on each desired-active cache zone. False is
the default, so all existing v1 configs remain syntactically unchanged. Every
threshold comes from the already validated closed install-v1 schema, not
caller-supplied raw directive text. No repository override is invented for
this filesystem-wide disk pressure threshold. An invalid capability type,
invalid document, unsupported/active repository or unsafe upstream is
rejected before a candidate can be returned.

IMPORTANT: a caller-supplied boolean does NOT prove that the installed
native binary accepts min_free and never authorizes NGINX installation or
activation. The result always reports native_min_free_supported_verified=false
and authorizes_nginx_activation=false. A future authorized locked installer
must independently probe the actual installed binary and validate the
exact full candidate with nginx -t, recording whether the enhanced form
works. If it does not, the original baseline without min_free remains a
separate, conservatively labelled fallback candidate; production disk-space
enforcement and failover are not proven by it.

The existing disposable two-distro stock NGINX runtime workflow invokes the
actual renderer in both modes, inspects exact min_free bytes from the
approved document and checks the full candidate against the installed NGINX
using nginx -t. Unlike the earlier string-injection experiment, it verifies
the actual shipping renderer. This only exercises syntax capability and
policy byte construction: no live eviction, ENOSPC, disk-pressure recovery,
systemd/SELinux, installed configuration or production activation is claimed.

Original #97 policy, cache churn/capacity measurements and safety acceptance
remain open. Do not merge a claim of working min_free or a real live host
without executed native evidence.
