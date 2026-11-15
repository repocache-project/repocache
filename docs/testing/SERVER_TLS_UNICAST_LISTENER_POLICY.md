# HTTPS listener bind-address safety (#30)

The closed version-1 installation schema now rejects IPv4 and IPv6
**multicast** addresses and IPv4-mapped IPv6 literals, even if the text
is a canonical IP. These are not unambiguous local unicast TCP listener
targets for an operator-controlled HTTPS cache. Otherwise an inert
firewall intent could be generated from an address whose binding or
address-family exposure is semantically unsafe.

The parser continues to accept canonical local unicast IP addresses,
loopback and explicitly requested wildcard IPv4/IPv6 binds; wildcard
exposure still needs separate firewall and active listener review.
Negative tests cover multicast address families and canonical mapped
IPv6 spellings before any host operation. All input mutation and
permission flags remain absent.

This is a strict input-safety refinement for #30, not production firewall
configuration, OS package authorization or NGINX activation. Real
kernel bind/firewall owner state, production certificate/CA trust,
AlmaLinux SELinux context and booted-target acceptance remain
NOT VERIFIED.

## Reserved IPv4 and limited broadcast (common install schema)

In addition to multicast and IPv4-mapped literals, the version-1 installation
validator now refuses canonical IPv4 Class-E addresses (`240.0.0.0/4`),
including the limited broadcast `255.255.255.255`. These are not usable
unicast TLS bind targets. The refusal is enforced **before** either the
non-authorizing NGINX listener candidate or the separate firewall intent
can be derived, whether firewall modification was requested or not.

Debian 13 and AlmaLinux 10 regression cases cover both installation
validation modes, both explicit firewall choices, both downstream
candidate boundaries and input immutability. Normal loopback, selected
unicast and explicit wildcard addresses remain accepted. Nothing in this
source-only policy authorizes a firewall modification or an NGINX activation;
booted native operation remains NOT VERIFIED under #30/#19.
