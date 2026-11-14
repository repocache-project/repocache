# DNS sockaddr input-shape refusal for upstream pin candidates (#28)

The candidate refresh planner consumes a bounded, complete collection of
Linux `getaddrinfo` tuples and emits only explicitly checked public IP
pins. The built-in isolated resolver normally returns validated JSON, but
the planner also supports a separately supplied resolver adapter. The
latter must not be able to cause an unhandled `TypeError` or an
ambiguous candidate by returning non-string socket addresses or numeric
coercions for socket family/type/protocol fields.

The planner now validates each socket record's **exact tuple shape**,
string canonical name/address, integral-but-not-bool socket fields, and
expected family/type/protocol/port before evaluating address size, family
or public-IP safety. Standard Python socket enumerations remain accepted,
as they are integer subclasses. A malformed record raises the same
redacted `UpstreamRotationError`, never produces a partial set of pins,
and therefore enters the existing bounded scheduler retry path.

Unit regressions exercise null, integer and bytes IPv4 addresses, bool
socket type, floating-point protocol, non-string canonical name and
malformed address tuple length, in addition to the prior private/reserved
IP and explicit non-default port tests. They run under the mandatory
Python 3.12/3.13 CI matrix.

No live DNS refresh daemon, root-worker privilege, NGINX activation,
catalog publication, signer, network policy change or host configuration
is introduced. An injected test resolver and even a well-formed public
pin set cannot establish DNS provenance or installed-host authorization.
These original #28/#19 gates remain NOT VERIFIED.
