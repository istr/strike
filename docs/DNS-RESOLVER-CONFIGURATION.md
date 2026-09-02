# DNS Resolver Configuration

Every strike lane must declare exactly one DNS-over-TLS (DoT)
resolver. The resolver is the only DNS path strike uses for a
lane run: peer FQDNs in the step's `peers:` list are resolved
by this resolver and no other, and the resolver's TLS identity
is captured in the deploy attestation alongside per-peer
identities. See ADR-028 for the architectural reasoning.

This document describes how to configure the resolver field.

## Minimal example

    resolver:
      adn: one.one.one.one
      ip: 1.1.1.1
      trust:
        type: caBundle
        path: /etc/strike/resolver-ca.pem

This is the full direct configuration of RFC 8310 section 7.1:
an authentication domain name and an IP address, both obtained
out of band.

The `adn` field is the authentication domain name. It is the
only server identifier: it is sent as the SNI and it is the
reference identifier the presented certificate chain is
verified against. An address literal in this field is rejected,
because RFC 8310 section 3 excludes IP addresses from that
role.

The `ip` field is the address the connection is routed to. It
routes and it authenticates nothing, and it must be a canonical
IP literal (IPv4 or IPv6, no port, no zone id). A name is
rejected: the resolver is itself the resolution authority and
cannot resolve its own hostname before it can be reached. Both
rules are enforced by `lane.validateResolver` at parse time, so
`strike validate` and `strike run` fail on the same input.

The `port` field is optional. Omitting it means 853, the DoT
port assigned by RFC 7858. Declare it only when the resolver
listens elsewhere.

The `trust` field is the CA bundle the presented chain is
verified against. It is the only anchor this endpoint accepts;
see "Why certFingerprint is rejected here" below.

## Public DoT resolvers

The three major public DoT services are usable directly. Each
publishes an authentication domain name and several addresses;
the lane declares one address (strike does not currently
support multiple resolvers per lane). The IPv6 alternative is
shown as a second `ip` value -- pick one.

### Cloudflare

    resolver:
      adn: one.one.one.one
      ip: 1.1.1.1
      # ip: 2606:4700:4700::1111
      trust:
        type: caBundle
        path: /etc/strike/resolver-ca.pem

Other addresses: `1.0.0.1`, `2606:4700:4700::1001`.

### Quad9

    resolver:
      adn: dns.quad9.net
      ip: 9.9.9.9
      # ip: 2620:fe::fe
      trust:
        type: caBundle
        path: /etc/strike/resolver-ca.pem

Other addresses: `149.112.112.112`, `2620:fe::9`.

### Google Public DNS

    resolver:
      adn: dns.google
      ip: 8.8.8.8
      # ip: 2001:4860:4860::8888
      trust:
        type: caBundle
        path: /etc/strike/resolver-ca.pem

Other addresses: `8.8.4.4`, `2001:4860:4860::8844`.

## Self-hosted DoT resolver: IPFire

Operators with control over their own DNS infrastructure can
run a DoT-capable resolver locally. IPFire is the open-source
example named in ADR-028; Unbound with stunnel, dnsdist, or
similar setups work equivalently. The pattern in the lane is
the same; only the name, the address, and the trust anchor
differ.

    resolver:
      adn: dns.internal.example
      ip: 192.168.10.1
      trust:
        type: caBundle
        path: /etc/strike/internal-ca.pem

The resolver's certificate must carry `dns.internal.example` in
its subjectAltName, and the bundle must contain the CA that
issued it. A self-signed leaf works only if that same leaf is
the bundle, which makes the certificate its own issuer -- it is
simpler to run an internal CA and issue from it.

The `caBundle` path is a container-internal path; the executor
mounts the lane-relative bundle file there. See ADR-028 for
the mount mechanics.

## Obtaining a CA bundle

The anchor is the CA that issued the resolver's certificate,
not the certificate itself. Verification is the full RFC 5280
path validation, with the `adn` matched in subjectAltName only
-- never in the Subject.

For a public provider, the bundle is the ordinary public root
store, or the single root the provider documents. Most systems
already ship one; copy it to the path the lane declares:

    cp /etc/ssl/certs/ca-certificates.crt /etc/strike/resolver-ca.pem

For a self-hosted resolver, the bundle is the internal CA's
certificate in PEM form -- the same file the CA emitted when it
was created.

To confirm the chain and the name before writing the lane:

    openssl s_client -connect 1.1.1.1:853 -servername one.one.one.one \
      -CAfile /etc/strike/resolver-ca.pem -verify_return_error </dev/null

Adapt per provider: `-connect 9.9.9.9:853 -servername dns.quad9.net`,
`-connect 8.8.8.8:853 -servername dns.google`, or the internal
address and name for a self-hosted resolver. The `-servername`
argument is the `adn`; it sets SNI, and it is what the
certificate is checked against.

A bundle survives leaf rotation, which is the point of
anchoring on the issuer: public providers rotate leaf
certificates monthly to yearly, and none of that reaches the
lane. The bundle changes only when the issuing CA does.

## Why certFingerprint is rejected here

`trust.type: certFingerprint` is a parse error on the resolver
and valid on every other declared endpoint. RFC 8310 section
6.6 admits exactly two kinds of authentication information for
a DoT server: an authentication domain name obtained from a
section 7 source, or an SPKI pin set. A SHA-256 digest over the
leaf certificate is neither -- it pins the whole certificate
rather than the public key, and it identifies no name that a
certification path could be validated against. Pinning it would
make the resolver's address the thing being trusted, and
section 3 excludes addresses from that role.

The narrowing is the resolver's alone. Peers, the OIDC IdP, the
keyless endpoints, and the registry target all keep the full
`certFingerprint | caBundle` vocabulary. See ADR-028.

## Probe behavior

At the start of every `strike run`, strike performs a one-shot
DNS-over-TLS roundtrip against the declared resolver as a
pre-flight check. The probe verifies, in a single TLS
handshake plus one DNS query, that:

- the resolver's TLS endpoint is reachable at the declared
  address and port
- the certificate the resolver presents is issued by the
  declared CA bundle and names the declared `adn`
- the resolver responds to DNS queries over the established
  TLS connection

The probe target is an NS query on `.` (the DNS root zone),
which every standards-compliant DoT resolver answers. This
avoids encoding any provider-specific sanity name in strike's
code or in the lane schema.

If the probe fails, the lane run aborts before any DAG
construction, before any step container starts, with a single
error line identifying which resolver was probed.

### Probe runs at `strike run`, not at `strike validate`

`strike validate` is a pure offline syntactic and semantic
check of the lane file. Its result is a property of the lane
file alone: schema conformance, path canonicalization, peer
trust-mode discrimination, image-pinning constraints. Two
invocations on the same file, on the same machine or
different machines, in this hour or in five years, will
return the same answer.

The probe's outcome is a property of the environment at probe
time -- whether the resolver address is reachable from this
network at this moment, whether the certificate it presents
still validates against the declared bundle, whether
intervening middleboxes pass TLS 1.3 on port 853. None of
these are functions of the lane file.

Folding the probe into validation would make `strike validate`
network-dependent, would silently invalidate today's
validation result when tomorrow's resolver certificate stops
chaining to the declared bundle, and would conflate input
properties with environmental state. The probe therefore lives
at `strike run`, where the network is required anyway and where
a probe failure prevents wasted setup work for a run that could
not have succeeded.

Operators who want explicit resolver reachability checking
outside of a run -- for example as part of a CI pipeline that
verifies lane configurations before scheduling them -- can
invoke `strike run` with a no-op lane or, in the future, may
use an explicit opt-in flag on `strike validate`. The
automatic-probe-in-validate path is not supported by design.

### Probe is not attested

The probe's roundtrip result does not enter any signed payload.
It is an operational pre-flight check: did the resolver answer
at startup? The per-step DNS resolutions that DO feed deploy
attestation -- FQDN-to-IP records, the resolver's captured TLS
identity at the moment of resolution -- are produced by the
allowlist resolver and are separate from the pre-flight
probe.

### Probe identity capture

Beginning with ADR-030, the probe also captures the resolver's
observed TLS identity -- leaf certificate fingerprint and
negotiated TLS version and cipher suite -- and records it in the
deploy attestation under `resolver`. Both halves of the dial are
recorded: `host` is the verified identity, the authentication
domain name and its port, and `dialedIP` is the address the
socket actually connected to. Routing and identity are two
values, so the attestation carries them as two fields rather
than one packed authority.

DNS answers are not content-addressable, so the resolver's
channel identity is part of the trust chain; the attestation
records what the verified handshake observed, for a verifier to
compare against the lane's declared resolver trust anchor.
