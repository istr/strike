# ADR-007: Asymmetric Identity for Client Auth and Server Trust

## Status

Accepted.

## Context

Authentication in CI/CD systems often collapses two distinct trust
questions into one configuration object: "who am I to the remote
peer" (client identity) and "which peers do I trust" (server
identity). A single PAT, a single SSH config, a single OIDC token is
treated as the answer to both. This works only when the underlying
protocol does not actually distinguish them, which is rare.

Consider SSH for git: the agent provides signing power without
revealing key material; the agent answers "who am I". The client's
`known_hosts` file answers "which servers do I trust". The two are
delivered through different protocol layers, by different mechanisms,
and the agent fundamentally cannot answer the second question -- it
does not know what hosts will be contacted. Treating ssh-agent and
known_hosts as one trust configuration produces a false-consolidated
anchor that no underlying protocol actually supports.

The same shape recurs across every protocol strike interacts with:

- HTTPS: client cert (client identity, optional) vs CA bundle / cert
  fingerprint (server identity, required).
- OCI registries: registry credentials (client identity) vs image
  digest (server identity, content-addressed).
- KMS / OIDC workload identity: signing delegation (client identity)
  vs the keys/certs used to verify what KMS signs (server identity).

## Decision

Client identity and server identity are attested independently and
carried by different mechanisms. strike mediates but does not own
key material. Credential-holding authorities (ssh-agent, KMS,
OIDC workload identity, cosign keyless) delegate signing power
without exposing keys to strike.

In step specifications and deploy attestations, the two are recorded
separately:

- *Client identity*: the credential reference used to authenticate
  to the peer (e.g. `ssh-agent` socket, KMS key URI).
- *Server identity*: the trust anchor used to verify the peer (e.g.
  known_hosts entry, certificate fingerprint, CA bundle, OCI image
  digest).

Bundling the two into a single trust configuration field is
prohibited.

## Consequences

- The lane schema has separate fields for "what credential" and
  "what trust anchor". Mixing them in one field is a parse error,
  not a runtime warning.
- Workload identity migrations (PAT to OIDC, static keys to KMS)
  affect only the client-identity side; server trust is unaffected.
  And vice versa: rotating a CA does not require touching credential
  configuration.
- Deploy attestations record both sides explicitly. A verifier can
  see what credential was used (e.g. "this was signed by a
  key-manager-resident key with this thumbprint") and what trust was
  used (e.g. "the OCI registry served us images verified against
  these digests"), without conflating them.
- The `internal/container` engine identity captures this for the
  controller-engine link: server cert fingerprint and client cert
  fingerprint live in separate fields of `EngineRecord`, and the
  connection type ("unix", "tls", "mtls") makes the asymmetry
  explicit.

## Principles

- Identity is asymmetric
- Peers are declared

## Amendment 2026-10-31 -- "record both sides explicitly" is read per side (ADR-058 D8)

The consequence "Deploy attestations record both sides explicitly" is
read, from this date, as "both sides declared separately, each recorded
where it is verifiable". The server side of a registry push is recorded
as observed (`#PushedArtifact`, `#ObservedTLS`). The client side is
recorded where a verifier can check it: the keyless signing identity in
the sealed provenance and the Rekor entry. A bearer credential's
identity is the registry's knowledge, not the record's;
[ADR-058](ADR-058-registry-client-identity-workload-token.md) D8
declines to carry it. The decision text and the example in the
consequence stand.
