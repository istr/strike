# ADR-032: Peer TLS version floor

## Status

Accepted. Supersedes in part ADR-008 (cryptographic primitives) and the
earlier TLS-1.3-minimum requirement, which mandated TLS 1.3 on every hop.

## Context

strike establishes TLS on hops of two kinds:

- Controlled hops, where strike controls at least the modern end:
  strike <-> Podman engine (mTLS), and the container tool <-> mediator
  client side (the mediator presents the ephemeral cert).
- External-peer hops, where the peer's TLS version is outside strike's
  control: the declared DoT resolver, and the mediator's upstream to a
  declared HTTPS peer.

Mandating TLS 1.3 everywhere breaks reachability to legitimate peers
that cap at TLS 1.2. This is not hypothetical: registry.npmjs.org caps
at 1.2 (an `openssl -tls1_3` handshake to it returns a protocol_version
alert), so npm could not be mediated. A CI/CD tool that must reach the
real internet cannot dictate the peer's TLS version.

BSI TR-02102-2 (2026-01) recommends TLS 1.3 in preference and TLS 1.2
through end of 2031; TLS 1.0 and 1.1 are not recommended.

## Decision

- Controlled hops keep a TLS 1.3 minimum. strike controls the modern
  end; there is no reachability cost.
- External-peer hops (DoT resolver and mediator upstream, which share
  transport.BuildTLSConfig) floor at TLS 1.2 and prefer 1.3. The TLS
  1.2 cipher set is restricted to the BSI TR-02102-2 AEAD/ECDHE (PFS)
  suites that Go supports: ECDHE-ECDSA/RSA with AES-128/256-GCM. CBC,
  AES-CCM, and ChaCha20-Poly1305 are excluded (rationale in the code
  comment on bsiTLS12CipherSuites). The TLS 1.3 cipher set is fixed by
  Go and not restrictable; per BSI's own note, suites not on its list
  are not thereby insecure.
- Anything below TLS 1.2 is rejected. The rejection is diagnosed, not
  opaque: the mediator logs the upstream failure (WARN), and the
  resolver pre-flight fails with a named error. The container still
  receives only the wire-level close.

## Sunset

BSI discontinues its TLS 1.2 recommendation at end of 2031 (quantum-
safe key agreement is not standardised for 1.2). Revisit this floor by
2031: either raise external peers to 1.3-only, or adopt the hybrid
quantum-safe mechanisms BSI will recommend.

## Consequences

- npm and other 1.2-only public peers become reachable through the
  mediator.
- Peers that speak only TLS < 1.2, or only non-BSI cipher suites on
  1.2, are not supported and fail with a clear diagnostic -- the same
  "unsupported practices are not supported, but well-diagnosed" stance
  applied elsewhere.
- The asymmetry (1.3 controlled, 1.2 external) is deliberate and
  localised to one function; controlled hops are unweakened.

## Principles

- **Restricted by default, relaxed only with reason.** Controlled hops
  keep a TLS 1.3 minimum; the floor drops to TLS 1.2 only on external-peer
  hops, only because real peers (e.g. registry.npmjs.org) cap at 1.2, with
  the cipher set bounded to the BSI TR-02102-2 AEAD/ECDHE suites and a 2031
  horizon. Anything below TLS 1.2 is rejected, with a diagnosed failure.
- **Peers are declared.** The relaxation applies precisely to the
  declared-peer dial path (DoT resolver, mediator upstream), not to
  controller-internal hops.
- **Code is liability.** Both relaxed hops share one
  `transport.BuildTLSConfig`; there is no per-consumer TLS configuration.
