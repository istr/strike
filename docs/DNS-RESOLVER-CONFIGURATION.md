# DNS Resolver Configuration

Every strike lane must declare exactly one DNS-over-TLS (DoT)
resolver. The resolver is the only DNS path strike uses for a
lane run: peer FQDNs in the step's `peers:` list are resolved
by this resolver and no other, and the resolver's TLS identity
is captured in the deploy attestation alongside per-peer
identities. See ADR-028 for the architectural reasoning.

This document describes how to configure the resolver field
today. Two enhancements documented at the end as "Future
direction" are planned but not yet implemented.

## Minimal example

    resolver:
      host: "1.1.1.1:853"
      trust:
        mode: cert_fingerprint
        fingerprint: sha256:<obtain via openssl, see below>

The `host` field is an IP literal (IPv4 or IPv6) with an
explicit port. The `trust` field is the same
`cert_fingerprint | ca_bundle` discriminated union used by
HTTPS peers. FQDNs are rejected for the host: the resolver
is itself the resolution authority and cannot resolve its
own hostname before it can be reached. The rejection is
enforced by `lane.validateResolver` at parse time, so both
`strike validate` and `strike run` fail on the same input.

## Public DoT resolvers

The three major public DoT services are usable directly with
fingerprint pinning. Each has primary and secondary endpoints;
the lane declares one (strike does not currently support
multiple resolvers per lane).

### Cloudflare

IPv4 endpoints: `1.1.1.1`, `1.0.0.1`
IPv6 endpoints: `2606:4700:4700::1111`, `2606:4700:4700::1001`
Port: 853
Certificate hostname (for verification when D14 lands):
`one.one.one.one`

Example:

    resolver:
      host: "1.1.1.1:853"
      trust:
        mode: cert_fingerprint
        fingerprint: sha256:<obtain via openssl, see below>

### Quad9

IPv4 endpoints: `9.9.9.9`, `149.112.112.112`
IPv6 endpoints: `2620:fe::fe`, `2620:fe::9`
Port: 853
Certificate hostname: `dns.quad9.net`

Example:

    resolver:
      host: "9.9.9.9:853"
      trust:
        mode: cert_fingerprint
        fingerprint: sha256:<obtain via openssl, see below>

### Google Public DNS

IPv4 endpoints: `8.8.8.8`, `8.8.4.4`
IPv6 endpoints: `2001:4860:4860::8888`, `2001:4860:4860::8844`
Port: 853
Certificate hostname: `dns.google`

Example:

    resolver:
      host: "8.8.8.8:853"
      trust:
        mode: cert_fingerprint
        fingerprint: sha256:<obtain via openssl, see below>

## Self-hosted DoT resolver: IPFire

Operators with control over their own DNS infrastructure can
run a DoT-capable resolver locally. IPFire is the open-source
example named in ADR-028; Unbound with stunnel, dnsdist, or
similar setups work equivalently. The pattern in the lane is
the same; only the IP and the trust anchor differ.

Example with a self-signed certificate:

    resolver:
      host: "192.168.10.1:853"
      trust:
        mode: cert_fingerprint
        fingerprint: sha256:<obtain via openssl from the local resolver>

Example with a CA-bundle-issued certificate (internal CA):

    resolver:
      host: "192.168.10.1:853"
      trust:
        mode: ca_bundle
        path: /etc/strike/internal-ca.pem

The `ca_bundle` path is a container-internal path; the executor
mounts the lane-relative bundle file there. See ADR-028 for
the mount mechanics (Phase 2).

## Obtaining a certificate fingerprint

Strike's `cert_fingerprint` trust mode requires the SHA-256
fingerprint of the resolver's TLS server certificate. Obtain
it once via `openssl s_client`, then paste into the lane.

For Cloudflare:

    openssl s_client -connect 1.1.1.1:853 -servername one.one.one.one </dev/null 2>/dev/null \
      | openssl x509 -fingerprint -sha256 -noout \
      | sed 's/.*=//; s/://g; s/.*/sha256:&/' | tr A-Z a-z

Output looks like:

    sha256:<64 lowercase hex characters>

Adapt the command per provider:

- Quad9: `-connect 9.9.9.9:853 -servername dns.quad9.net`
- Google: `-connect 8.8.8.8:853 -servername dns.google`
- Self-hosted: `-connect <ip>:853 -servername <whatever the cert SAN says>`

The `-servername` argument sets SNI. While strike today does
not verify the cert against SAN/CN (fingerprint pinning makes
the hostname irrelevant for trust), most DoT services require
SNI to route to the correct cert during the handshake. Use
the provider's documented hostname.

### When to refresh

Re-run the openssl command and update the lane when:

- The provider announces certificate rotation. Cloudflare,
  Quad9, and Google rotate roots and intermediates on multi-year
  cycles, but leaf certs (which is what fingerprint pinning
  typically captures) rotate more often -- monthly to yearly.
- The operator renews the self-hosted resolver's certificate.

Use `ca_bundle` mode instead of fingerprint pinning if cert
rotation cadence makes fingerprint maintenance burdensome.

## Probe behavior

At the start of every `strike run`, strike performs a one-shot
DNS-over-TLS roundtrip against the declared resolver as a
pre-flight check. The probe verifies, in a single TLS
handshake plus one DNS query, that:

- the resolver's TLS endpoint is reachable on the declared port
- the declared trust anchor (fingerprint pin or CA bundle)
  matches the certificate the resolver currently presents
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
time -- whether the resolver IP is reachable from this
network at this moment, whether the pinned certificate is
still the one the resolver presents (leaf certs rotate
monthly to yearly on public DoT providers), whether
intervening middleboxes pass TLS 1.3 on port 853. None of
these are functions of the lane file.

Folding the probe into validation would make `strike validate`
network-dependent, would silently invalidate today's
validation result when tomorrow's resolver cert rotates, and
would conflate input properties with environmental state.
The probe therefore lives at `strike run`, where the network
is required anyway and where a probe failure prevents wasted
setup work for a run that could not have succeeded.

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
Phase-2 allowlist resolver and are separate from the pre-flight
probe.

## Future direction

Two enhancements are architecturally agreed but not yet
implemented. Both are tracked as D-series decisions in
`ROADMAP-ADR-028.md`.

### D14: Combined IP + hostname declaration

Today the lane declares only an IP literal. TLS trust is via
fingerprint pin; the hostname in the certificate's SAN/CN is
not verified.

The planned enhancement:

- The lane declares both an IP (connection endpoint) and a
  hostname (verification anchor) for the resolver.
- Strike connects to the declared IP.
- During the TLS handshake, strike sends SNI for the declared
  hostname and verifies the certificate's SAN/CN against it.
  Verification is *in addition to* the existing fingerprint or
  CA-bundle check, not instead of it.
- Once the resolver is reachable, strike performs a one-shot
  cross-check: resolve the declared hostname through the
  resolver itself and confirm that the result includes the
  declared IP. If not, abort the lane.

Why deferred: basic functionality works without this. The
cross-check is a hardening property that closes a subtle
failure mode (operator declares the wrong IP for the right
hostname, or vice versa), but fingerprint pinning already
rejects the wrong-IP-different-cert case.

Why planned: it brings the resolver declaration in line with
how DoT is typically configured elsewhere (Android Private
DNS, systemd-resolved, OpenWrt all use IP plus hostname), and
it makes the lane self-validating against the resolver's own
DNS view.

### D15: Port-853 default

Today the lane must include the port in the host string
(`1.1.1.1:853`). The schema does not enforce that the port is
853 specifically; any port that resolves the IP-with-port
parse is accepted.

The planned enhancement: omit the port and default to 853
(RFC 7858). `host: "1.1.1.1"` would be equivalent to
`host: "1.1.1.1:853"`.

Why deferred: explicit-port-in-host is consistent with how
`:443` is not defaulted elsewhere in the lane (HTTPS peers
declare the port if non-standard, but for the rare
nonstandard case the explicit form is preferable). The
default is convenience; the present form works.

Why planned: 99% of DoT deployments use port 853. Requiring
`:853` in every lane is boilerplate. A default with the
explicit form still accepted (and overriding for nonstandard
ports) is the natural next step.
