# HTTPS TLS SNI and HTTP Host binding for cache routes (#30)

An HTTPS connection with a valid TLS certificate can still carry a different
HTTP Host header; conversely a valid HTTP Host is insufficient to authenticate
the TLS server name selected by the client. In shared-listener or default-server
scenarios, both must be bound to the exact operator-reviewed DNS hostname.

The non-activating NGINX TLS candidate now emits a fixed, escaped and
case-insensitive `$ssl_server_name` check in the server context. **Missing,
unrelated or mismatched SNI** returns HTTP 421 before managed cache routes
execute. Correct DNS SNI remains compatible, including case-insensitive DNS
spelling. The HTTP Host authority check is independently implemented and
reviewed under #336 and its follow-up #346; both gates must be retained
when the eventual trusted NGINX composer is activated.

The isolated Debian 13 / AlmaLinux 10 native stock-NGINX smoke establishes
a trusted synthetic TLS handshake, deliberately suppresses only the *test
client's* hostname comparison to submit absent or foreign SNI, and asserts
a real 421 response with no protected payload. Normal trusted certificate
and hostname verification remains enabled for successful requests.

No production certificate material, firewall port, systemd unit, TLS private
key, root-managed configuration, catalog or service is modified. Installed
operator authority, native SELinux and booted-host TLS exposure under #30/#19
remain NOT VERIFIED.
