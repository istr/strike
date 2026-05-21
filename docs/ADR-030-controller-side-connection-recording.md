# ADR-030: Controller-side connection recording follows the trust chain, not the connection count

## Status

Accepted. Extends the "Runtime is attested" principle and is bounded
by [ADR-001](ADR-001-engine-via-api-not-exec.md) (engine and registry
are untrusted; the trust anchor is independent content verification
against the declared hash). Refines
[ADR-028](ADR-028-step-container-egress-mediation.md) (whose
"Attestation surface" section named a `dns_resolver` record as
planned) and is consistent with
[ADR-012](ADR-012-engine-identity-capture.md) (engine transport
identity, informational) and
[ADR-029](ADR-029-peers-are-container-egress.md) (peers are
container-egress contracts only).

## Context

strike makes several kinds of external network connection. Some are
made by the *container* during step execution (HTTPS and SSH peers,
handled by ADR-028/ADR-029). Others are made by the *controller*: the
container engine, the DoT resolver, and OCI registry pull/push.

Removing the OCI peer type (ADR-029) raised the question of how the
controller-side connections should appear in the attestation, and
whether "observed but not declared" is a coherent category. An earlier
draft of this ADR proposed recording an observed TLS identity for all
four controller-side connections (engine, resolver, OCI pull, OCI
push), reusing the `transport.ConnectionIdentity` capture type.

Verifying the codebase against that proposal showed it was wrong for
OCI, and the reason is foundational rather than incidental.

## The governing constraint: ADR-001

[ADR-001](ADR-001-engine-via-api-not-exec.md) establishes that the
container engine is untrusted: "The controller signs only digests it
has independently verified. Engine self-reports are not trusted. A
compromised engine cannot read controller secrets; it can return bad
data, which the controller catches via independent verification."

This extends to the registry. The base-image pull runs through the
engine API (`Engine.ImagePull` -> Podman performs the registry
contact), and the controller never establishes the registry TLS
connection itself. What the controller does is independent: it
computes the expected manifest digest with `go-containerregistry`
(`img.Digest()`), and verifies the engine-reported digest against it
(`loadTagVerify`, `WrapImageOutputAsImage`):

    controllerDigest := v1HashToDigest(expectedHash)
    if engineDigest != controllerDigest {
        return fmt.Errorf("digest mismatch: controller=%s engine=%s", ...)
    }

The trust anchor for an inbound image is the controller-computed
content hash matched against the declared digest pin -- not the
identity of whatever served the bytes. A compromised registry, a
MITM, or a lying engine all fail the same digest check.

## Decision

**Controller-side connection recording follows the trust chain.** A
connection's identity is recorded in the attestation only when that
identity is part of the trust chain. Recording an identity that
contributes nothing to trust would be misleading: it would suggest the
attestation depends on something it does not.

The controller-side connections sort into exactly three cases:

### 1. DoT resolver -- recorded, because it is the trust anchor

DNS resolution has no content-addressable answer. The mapping
`name -> IP` is exactly what is queried and may legitimately change,
so there is no digest to fall back on. The only integrity mechanism is
the channel: a declared resolver with a declared trust anchor
(`resolver: {host, trust}`), verified at the TLS handshake.

Here the observed connection identity *is* the trust: the lane
declares which resolver and which anchor, and the attestation must
record that the resolver strike actually reached presented an identity
matching that anchor. strike establishes this TLS connection itself
(`transport.DialVerified` inside the DoT path), so the identity is
observable and is captured with `transport.ConnectionIdentity`.

**This is the one controller-side connection whose observed identity
is newly recorded by this ADR's implementation.**

### 2. Container engine -- recorded, but informational only

The engine transport identity is already captured and embedded
(`#EngineRecord`, ADR-012): connection type, cert fingerprints,
self-reported rootless/version. Per ADR-001 this is explicitly *not*
trusted -- it is informational context for a verifier assessing the
build environment, not a link in the trust chain. It stays as-is. This
ADR adds nothing to it and removes nothing from it.

### 3. OCI registry (pull and push) -- not recorded

The registry is untrusted (ADR-001). For a pull, the trust anchor is
the controller-computed digest matched against the declared pin; the
registry's TLS identity contributes nothing to that and, because the
engine performs the pull, is not even observable by the controller.
For a push, the artifact digest is controller-known and already
recorded as artifact provenance; the push destination is a routing
fact, and the push registry's identity likewise contributes nothing to
trust.

Recording a registry connection identity would therefore be both
impossible (not observable through the engine API) and misleading
(implying a trust dependency that ADR-001 explicitly disclaims). **OCI
registry connections get no trust declaration and no identity
recording.** The image digest pin -- already present in the lane and
already verified and recorded as artifact provenance -- is the
complete and only OCI trust artifact.

This completes the trajectory of ADR-029: the OCI peer was removed
because it was an empty *declaration*; the OCI connection identity is
not recorded because it would be an empty *observation*. OCI trust is
content trust, end to end.

## The principle, stated generally

An external connection's identity is recorded in the attestation
**when and only when it participates in the trust chain**:

- **Channel is the anchor (no content anchor available).** Record the
  observed identity and verify it against a declared anchor. The DoT
  resolver is the instance: DNS answers are not content-addressable,
  so the resolver's channel identity is the trust, and it is both
  declared and recorded.
- **Content is the anchor.** The connection's identity is irrelevant
  to trust; do not record it as a trust artifact. The content hash is
  recorded instead (and already is, as digest pins and artifact
  provenance). OCI pull/push are the instances.
- **Neither -- substrate.** The container engine is the execution
  substrate, not a build-time trust dependency. Its identity is
  recorded as informational environment context (ADR-012), explicitly
  outside the trust chain.

This supersedes the "record everything observed" framing of the
earlier draft. Recording is not universal; it is exactly as wide as
the trust chain. Identity that anchors trust is recorded; identity
that does not is either omitted (OCI) or marked informational
(engine). This is the stronger and more honest position, and it is the
direct consequence of ADR-001.

### Routing declaration vs. trust-anchor declaration

A destination being declared (a routing fact: "the image is at this
ref", "push to this registry", "resolve via this host") is distinct
from a trust anchor being declared (a verification fact: "and the
peer's identity must match this"). The OCI image ref and the push
registry are routing declarations; they are not trust anchors, and the
digest pin -- not the registry identity -- is what anchors OCI trust.
Conflating routing with trust was the original OCI-peer error
(ADR-029); this ADR keeps them distinct.

## The controller-side connections

| Connection | In trust chain? | Trust anchor | Recorded |
| --- | --- | --- | --- |
| DoT resolver | yes (channel; no content anchor for DNS) | declared `resolver.trust`, verified at handshake | observed identity -- **to implement** |
| Container engine | no (substrate; ADR-001 untrusted) | none (informational only) | informational identity -- yes (ADR-012, implemented) |
| OCI pull | no (content anchor: digest pin) | controller-computed digest vs. declared pin | image digest, as artifact provenance -- already recorded; no connection identity |
| OCI push | no (content anchor: artifact digest) | controller-known artifact digest | artifact digest -- already recorded; no connection identity |

The per-peer container connections (HTTPS via the mediator, SSH) are
in the trust chain on the container-egress side; their recording is
the per-peer `connections` surface ADR-028 describes, captured by the
mediator with the same `transport.ConnectionIdentity`, and is tracked
with the Phase-2 attestation wiring -- separate from this
controller-side set.

## Shared capture structure

The connections whose identity *is* recorded as a trust artifact --
the DoT resolver here, and the per-peer mediator connections in the
Phase-2 wiring -- share one capture type:
`transport.ConnectionIdentity`, captured by
`transport.CaptureIdentity(state, addr)` (peer cert chain, leaf
SHA-256 fingerprint, negotiated TLS version, cipher suite, SNI, peer
address). The mediator already populates it per upstream connection;
the resolver record reuses it. One capture mechanism, consistent with
"Code is liability."

The engine record (`#EngineRecord`) predates the shared type, carries
self-reported fields the others lack, and may describe a Unix socket
with no TLS handshake; it stays as-is. OCI introduces no capture
structure, because it records no connection identity.

## Consequences

- The deploy attestation gains exactly one new controller-side
  record: the DoT resolver's observed TLS identity, captured once per
  lane run at the DoT handshake and verified against the declared
  resolver trust anchor. This closes the `dns_resolver` gap ADR-028
  named.
- The engine record is unchanged (informational, ADR-012).
- OCI registry connections gain nothing: no declaration, no recording.
  The digest pin remains the sole OCI trust artifact, consistent with
  ADR-001 and completing ADR-029.
- "Runtime is attested" is sharpened to "the trust chain is attested":
  every identity the attestation records is one trust actually depends
  on. A verifier reading the attestation does not encounter recorded
  identities that look load-bearing but are not.
- No new declaration burden on lane authors. The resolver declaration
  already exists; OCI registries are not declared with trust anchors
  (the digest pin is the anchor); the engine is operator-configured.

## Implementation

In the instruction following ADR-029's OCI-peer removal:

- Add the DoT resolver connection record to the deploy attestation.
  The DoT path (`transport.LookupHost` / `ProbeResolver`, via
  `dotResolver`'s `DialVerified` dial) already establishes a verified
  TLS connection; capture its `ConnectionIdentity` once per lane run
  (the resolver identity is stable across a run; ADR-028: "captured
  once, on the first DoT handshake; applies to all resolutions in this
  run") and embed it in the attestation alongside the engine record.
- Do not add any OCI registry record. Do not add any registry trust
  declaration.
- Leave the engine record unchanged.

The exact field name and the attestation-schema shape for the resolver
record are settled in that instruction. The architectural commitments
here are: recording tracks the trust chain; the resolver's channel
identity is the one new recorded controller-side trust artifact; OCI
records content (the digest), never connection identity; the engine
record stays informational.
