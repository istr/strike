# ADR-056: The TLS trust anchor is an inline certificate

## Status

Accepted, 2026-09-06. Grounded at `29b6893`. The anchor form, the `mode`
vocabulary, the self-signed requirement, the resolver unification, and the
DER encoding were ratified on 2026-09-06 before any instruction was
authored.

Reinforces rather than revises
[ADR-021](ADR-021-system-trust-store-deferral.md): its deferral of the
system trust store stands, and this record makes it structural, because
no anchor in this scheme can name a store at all. Displaces the
trust-anchor vocabulary clause of
[ADR-028](ADR-028-step-container-egress-mediation.md)'s amendment of
2026-09-01, which reads the resolver's anchor set as `caBundle` alone; the
subset property that clause establishes is preserved and strengthened
here. Consistent with [ADR-011](ADR-011-sources-elimination.md) (no
unaddressed host input), [ADR-037](ADR-037-two-engine-trust-layers.md)
(what a record's provenance is),
[ADR-039](ADR-039-deploy-step-as-attestation-root.md) (a verifier
cross-checks observed against declared), and
[ADR-055](ADR-055-hardened-endpoint-development-premise.md) (the reference
endpoint provides nothing beyond four capabilities).

**This is a freeze event.** `contract/endpoint` is imported into
`contract/attest` through `lane.#Peer`, so the declared-peer shape on the
attest wire changes. Under the Beta Definition of Done amendment of
2026-09-05 that makes this a beta-blocking ratification with a golden
rebaseline.

## Context

`README.md` opens with four promises. The first is "reproducible" and the
fourth is "no local toolchain". The TLS trust vocabulary as it stands
breaks both, and it breaks them at the same place.

`endpoint.#Trust` offers two anchors. `#Fingerprint` carries a SHA-256
digest over the leaf certificate. `#CABundle` carries `path`, an absolute
path that `transport.loadCABundle` reads in the controller's own
filesystem to build an `x509.CertPool`.

The path is the defect, and it has three distinct consequences.

**The anchor content is in no digest.** `registry.SpecHash` covers the
step's image digest, args, env, input hashes, and source hashes. The lane
digest covers the lane file, which contains the path string and not what
it points at. Two runs over an identical tree with an identical lane
accept different peer identities when the file behind the path changes,
and no digest moves. This is structurally the hole
[ADR-011](ADR-011-sources-elimination.md) closed for `sources:` -- an
unsigned, unaddressed input that can drift silently between runs -- moved
from the step side to the controller side.

**The anchor is opaque on the attest wire.** `contract/attest`'s `#Sealed`
carries `peers` as `[...lane.#Peer]`, the full declaration including its
trust anchor. For `#Fingerprint` that is a digest an offline verifier can
hold against the `serverCertFingerprint` in `observedPeers`, which is the
cross-check [ADR-039](ADR-039-deploy-step-as-attestation-root.md) D4
requires. For `#CABundle` it is a filesystem path. The verifier does not
know the filesystem in which that path held, and cannot learn it: the
builder identity is the constant string `https://istr.dev/strike`, not a
digest that identifies the controller. A bundle holding a single
self-signed root and a bundle holding the entire public web PKI are
indistinguishable on the wire. strike therefore attests its observations
checkably and its declarations only nominally.

**The anchor requires a file the reference endpoint does not provide.**
[ADR-055](ADR-055-hardened-endpoint-development-premise.md) D1 grants four
capabilities and states that a machine with more is a convenience nothing
may depend on. A bundle the operator must obtain, place, and bind-mount is
a fifth. That is what "no local toolchain" denies.

Neither existing anchor can be repaired into a form that is both checkable
and stable. `#Fingerprint` is checkable and pins the leaf, so it expires
with the leaf: quarterly for a public CA, twelve-hourly for the local
harness. `#CABundle` is stable and opaque. The vocabulary has no third
term.

## Decision

**D1. One anchor form.** `endpoint.#Trust` is a single shape that carries
the anchor itself. `#Fingerprint` and `#CABundle` are removed, and with
them `#TrustType` as a two-term vocabulary. No anchor names a path, a
store, or a digest of something held elsewhere.

**D2. The anchor is a DER-encoded X.509 certificate in standard padded
base64.** The field is `primitive.#Base64` -- the same primitive and the
same "no PEM armor" discipline `#HostKey.key` already carries for SSH. A
single-certificate encoding makes the anchor's breadth a property of the
format rather than a matter of authoring discipline: unlike PEM, it cannot
carry a bundle.

**D3. `mode` selects the binding breadth, and it is `rootca` or `leaf`.**
`rootca` is the default. The field is optional where a lane author may
change it and always concrete on the attest wire: the parser resolves the
default in Go, following the convention `#DoT.port` established, so a
verifier never has to know what an absent field meant. Every resolved
default is attested.

**D4. `rootca` requires a self-signed certificate.** Validation rejects an
anchor whose issuer and subject differ or whose signature does not verify
under its own key, in addition to requiring `BasicConstraints CA:TRUE`.
An intermediate is not an anchor here.

This is deliberate and it is the point of naming the mode `rootca` rather
than `ca`. Go accepts a non-root certificate in a root pool -- the CA
check in `CheckSignatureFrom` is bypassed when the certificate is itself
in the pool, which upstream has carried as an open issue since 2022. An
intermediate anchor would express a chain-shaped binding: narrower than a
root, broader than a leaf, and breaking on every intermediate rotation
while offering no protection against reissuance by the same CA. Where a
verifier cannot obtain the chain from public sources, failing is the
correct outcome.

**D5. `leaf` is an exact comparison, not a chain build.** The presented
leaf's DER must equal the declared DER byte for byte, checked in
`VerifyPeerCertificate`. The declared certificate never enters a root
pool, so nothing in this path depends on the Go behaviour D4 names.

**D6. The DoT resolver unifies to `rootca`.** `#DoT.trust` is
`#Certificate & {mode: "rootca"}`. RFC 8310 section 8.1 requires whole-chain
verification per RFC 5280 with the reference identifier matched in
subjectAltName; an inline root satisfies that and an inline leaf does not.
Unification rather than a separate type is what keeps
[ADR-028](ADR-028-step-container-egress-mediation.md)'s property
structural: the resolver's anchor set is a strict subset of a peer's, not
a different mechanism that merely resembles one.

**D7. Validation is where the mode and the certificate are reconciled.**
A declared mode inconsistent with the certificate's own constraints is a
hard failure at validate time, before any dial. `strike validate` is
therefore sufficient to reject a mis-declared anchor.

**D8. Fixtures carry one checked-in anchor built on an RFC 9500 test key.**
Every anchor in the tree that exists only so a parser has something to
parse -- test fixtures, golden lanes, documentation examples -- uses one
self-signed CA certificate over the P-256 key RFC 9500 names
`testECCP256`. The certificate is generated once, checked in, and reused
everywhere; the private key is not needed after generation and is not
checked in.

Four properties decide this over the alternatives. The key is publicly
catalogued as test material for exactly this purpose, with the same
intent as the EICAR file, so a scanner or a reader can recognise it
without knowing strike. The validity window is chosen at generation, so
the fixture set has no expiry date. The subject is chosen at generation
and names the certificate as a test anchor, so the identification travels
into every fixture and every error message. And P-256 is the curve the
project already uses throughout for DSSE and Rekor.

RFC 9500's Code Components are under the Revised BSD License; the key
material carries that notice where it is recorded.

This is a boundary against [ADR-018](ADR-018-ephemeral-test-material.md),
not an exception to it. ADR-018 governs material for the local sigstore
harness: keys and certificates belonging to a running service, which are
generated per harness build precisely because a long-lived copy of them
would be a standing credential. A fixture anchor belongs to no service.
It is never presented, never validated against a live peer, and holds no
authority anywhere. It is parser input, and the record it belongs in is
this one.

## Consequences

**The lane becomes self-contained.** Every anchor a lane relies on is in
the lane file, so the lane digest covers it. Two runs over an identical
tree and an identical lane cannot accept different peer identities. The
reproducibility promise gains a component it did not have.

**The declared side becomes checkable.** An offline verifier reading
`sealed.peers` holds the anchor certificate itself: subject, issuer,
validity window, key usage, constraints. Held against the
`serverCertFingerprint` in `observedPeers`, it supports a judgement about
how tightly the identity was bound, which a path never supported.

**No host file, no mount, no fifth capability.** The bind-mount question
disappears rather than being answered.

**Lanes grow.** A certificate is roughly 1.5 to 2 KB base64. A lane
pinning a resolver, an IdP, three keyless endpoints, a registry, and two
build peers grows by roughly 12 KB. Where several endpoints share an
anchor -- the local harness pins four of them to one Caddy root -- the
certificate repeats. Whether the YAML parser's anchor and alias syntax may
be used to collapse that repetition, and what the lane digest then covers,
is not settled by this record.

**One YAML scalar style is required.** `primitive.#Base64` admits no
whitespace. Measured against a YAML parser, the literal block style
preserves newlines and both the folded and plain multi-line styles fold
them into spaces; only a double-quoted scalar with backslash line
continuation yields a clean value. A lane author who wraps the anchor any
other way gets a validation failure, which is the correct outcome but not
an obvious one.

**Every declaration site changes.** `#Trust` is named at five places:
`lane.#OIDC.trust`, the deploy registry target's `trust`,
`endpoint.#HTTPS.trust`, `endpoint.#TLS.trust`, and `#DoT.trust`. Every
lane file in the tree, every fixture, and the golden lane change with
them.

**The goldens rebaseline.** The declared-peer shape on the attest wire
changes, so `internal/verify/testdata/golden` is regenerated. Per the Beta
DoD amendment of 2026-09-05 this is the beta-blocking ratification event
that amendment anticipates.

**One anchor rotation model replaces two.** A `rootca` anchor survives leaf
rotation and expires with the root, on a scale of years. A `leaf` anchor
expires with the leaf. Neither is new behaviour; the change is that the
choice is now visible in the lane and in the attestation.

**Fixtures gain a real certificate where they carried a placeholder.**
Today a fixture anchor is `sha256:0000...`, a value no parser looks at.
D7 makes the anchor parsed at validate time, so no placeholder survives:
every fixture, golden lane, and documentation example carries the D8
certificate. That is a one-time cost at the migration and none afterward,
since the certificate is one artifact reused everywhere.

## Alternatives considered

**Keep `caBundle` and enrich the observation instead.** Add the validating
root to `#ObservedTLS`, which `x509.Verify` already computes and
`ConnectionIdentity` already carries as `PeerCertificates`. This closes
the attestability gap and leaves the reproducibility gap open: the
declared anchor is still a path whose content can drift. It also still
requires a host file. Rejected because it addresses the smaller half of
the defect.

**Hash the bundle content into the attestation.** Rejected on the
operator's ground: a verifier cannot reconstruct a bundle from its digest,
so the digest establishes only that the content did not change between two
runs it can compare -- which is not what a verifier holding one
attestation is doing.

**SPKI pinning per RFC 7469 and RFC 7858.** The pin is a SHA-256 digest
over a certificate's DER-encoded SubjectPublicKeyInfo, matched against
every public key in the chain, walking upward until a pin matches. The
level is thus the declarer's implicit choice rather than a property of the
mechanism, which is why the standard recommends a backup pin. At leaf
level a key pin is worse than a certificate pin once the key rotates with
the certificate, as current guidance recommends: it breaks equally often
and shows a verifier nothing. At root level the key is as stable as the
certificate, so the pin buys nothing and costs the self-description.
Rejected in both breadths.

**PEM instead of DER.** Rejected on D2's ground: PEM admits multiple
blocks, which is exactly a bundle, and it costs block-count, block-type,
and trailing-data handling that DER does not.

**Pin the chain rather than the root.** A conjunction of root and
intermediate. It protects only against a CA that has already been
compromised into issuing under a different intermediate -- a threat whose
correct answer is leaf pinning -- while breaking on every intermediate
rotation. Go does not enforce it for free either: `VerifyOptions.Intermediates`
is a chain-building pool rather than a constraint, so enforcement means
inspecting the returned chains. Rejected as cost without a matching gain.

**A production root as the fixture anchor.** A real public root -- an
existing CA in the web PKI -- parses and is self-signed, so it satisfies
the mechanics. Rejected because a fixture is a template: copied as the
starting point for a real lane, it would silently declare a production CA
as a trust anchor. A fixture anchor has to be recognisable as one.

**Generating the fixture anchor per test run.** Rejected because it buys
nothing here and costs the property that makes D8 work. Generation per run
answers the standing-credential concern that governs harness material, and
a fixture anchor is not a credential. What it would cost is
recognisability: a freshly generated key looks like any other key, while
an RFC 9500 key is catalogued as test material.

**NIST PKITS.** A test suite for path validation, containing certificates
that are deliberately malformed and meant to be used as a set. Rejected as
the wrong shape for a single fixture anchor.

**An explicit mode with no default.** Rejected as a worse trade than D3:
requiring every author to state `rootca` adds noise to the common case,
and the concern that motivated it -- an absent field being ambiguous to a
verifier -- is answered by resolving the default in the parser rather than
by removing it.

## Principles

- **Reproducibility is enforced, not hoped for.** The anchor content moves
  inside the lane digest, so the set of identities a run will accept is a
  function of the lane file and nothing else.
- **External references are digest-pinned.** The last unaddressed input on
  the controller path becomes content, carried rather than referenced.
- **Peers are declared.** The declaration now states what it claims in a
  form a reader can evaluate, instead of naming a file that states it.
- **Runtime is attested.** The declared half of the peer record becomes as
  checkable offline as the observed half already was.
- **Observation over declaration.** The principle is preserved rather than
  weakened: the observed identity remains the fact, and the declaration
  becomes checkable enough that the cross-check between them is meaningful.
- **Restricted by default, relaxed only with reason.** No anchor can name
  a store, and `rootca` cannot name an intermediate; the narrow forms are
  the only forms.
- **Enforcement is structural, not discretionary.** A mis-declared anchor
  fails at validate time rather than at dial time, and a bundle cannot be
  declared at all because the format cannot express one.
- **Code is liability.** Two anchor types and a file-reading path are
  replaced by one type and a parse; `pem.Decode` and its error cases never
  enter the tree.
