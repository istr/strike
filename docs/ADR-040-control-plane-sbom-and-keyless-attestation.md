# ADR-040: Control-Plane SBOM Generation and Keyless Attestation

## Status

Accepted.

## Context

The control plane targets SLSA Build Level 3 when the container engine is
trusted, and degrades to L2+ when it is not -- retaining every L3 property
except the two that are provably unreachable without engine trust: complete
externalParameters and build isolation. The attestation architecture has to
make that degradation real, not aspirational.

The organizing principle is identity, not keys, and authority, not
implementation. The control plane is the attestation authority: it acts on the
sealed, post-exit artifact from outside, and the untrusted build container never
describes itself. Established ecosystem tooling does the mechanical work
(sigstore / Fulcio / Rekor / in-toto / a syft-class cataloger); strike drives it
and reimplements none of it, and nothing strike emits lives outside that
ecosystem.

Two things in the current implementation violate this and are the reason for
this ADR:

- The SBOM is generated from the packed Go binary's buildinfo (ADR-019 decision
  step 1). That describes a Go binary, not the artifact: the subject is
  hardcoded "strike", the component set is Go modules only. For strike's actual
  artifacts -- container images carrying npm, Hugo, OS packages -- this either
  fails (no binary in the pack: the observed `read build info from "": no such
  file` crash) or produces a wrong SBOM (wrong subject, missing real
  components). It is also a trust-layer error: an SBOM contributed by the build
  container is engine-relayed untrusted content, never independently
  establishable.
- Signing uses an operator-held key (ADR-019 decision step 3, "the same key used
  for the image"). The target is keyless: short-lived Fulcio-issued certificates
  bound to an OIDC identity, where the only durable secret is the identity.

"Code is liability" shaped the library choices, which were measured rather than
assumed: an osv-scalibr import-surface spike and a keyless import-surface spike.

## Decision

### D1 -- The control plane generates the SBOM in-process over the sealed artifact

The cataloger is osv-scalibr, used as a modular library: strike imports only the
extractors its lane ecosystems require -- today the npm lockfile extractor
(`.../language/javascript/packagelockjson`) and the Debian dpkg extractor
(`.../os/dpkg`) -- never the `extractor/filesystem/list` aggregator, which pulls
all extractors. Extraction runs over an already-extracted root filesystem
(`fs.FS`), never scalibr's container-image or disk-image scanner.

To shed the disk-image filesystem cluster (go-diskfs, go-ext4-filesystem,
go-ntfs) that scalibr's `extractor/filesystem` walker pulls unconditionally via
`embeddedfs/common`, strike drives the extractors through a thin in-process
`fs.FS` walker of its own (on the order of one hundred lines). The audited
extractors and the converter remain upstream; only the walk is strike's. This is
the project's "a little copying is better than a little dependency" applied
deliberately. In parallel, an upstream PR decouples `embeddedfs/common` from the
walker; once merged, strike drops its walker and returns to the upstream entry
point.

Output uses scalibr's converters in both formats: CycloneDX is canonical
(`application/vnd.cyclonedx+json`), and SPDX 2.3 is produced as a first-class
output -- it is a real requirement for certain consumption scenarios, not
hypothetical. cyclonedx-go ceases to be a direct strike dependency; it remains
transitive via scalibr at the identical version strike already pins (v0.11.0).
The SBOM document is canonicalized -- deterministic serial number and document
namespace, SOURCE_DATE_EPOCH timestamp, stable component ordering -- so that
byte-identical inputs yield byte-identical SBOMs.

The SBOM is a sealed (layer V) claim: it is produced from bytes the control
plane holds -- the image it assembled in-process, the same bytes it pushes and
whose digest it computes -- so it survives no-engine-trust. Base-image
components are obtained either from the base's own signed SBOM referrer (an
E-to-V lift by consumer-verifiable signed-digest dereference, using ADR-019's
resolution order, which is retained) or by cataloging the control-plane-pulled
base layers in-process; both are layer V.

The buildinfo `GenerateSBOM` path is removed in its entirety -- this is a
deletion, not a fix. A directory output that wraps with no file content is
surfaced at the producing step as an INFO line (the class of the original
crash), without affecting any verification.

**D1 amendment (measured; supersedes the mechanism above, not the decision).**
The decision stands: the control plane catalogs the sealed artifact in-process
over an `fs.FS`, emitting canonical CycloneDX and first-class SPDX 2.3 as
layer-V claims; the buildinfo path is removed; an empty directory output is an
INFO line. Two import-surface measurements revised the mechanism. First,
osv-scalibr's extractors cannot be imported without the disk-image cluster:
every filesystem extractor imports `extractor/filesystem -> embeddedfs/common
-> go-diskfs/go-ext4/go-ntfs` at import time, so the thin walker -- which
replaces only the walk -- cannot shed it, correcting the spike's conclusion.
Second, scalibr's converter-only path, while free of the disk-image cluster,
was measured to add ~12 modules / ~3--5 MiB, including a full go-git
implementation pulled for gitignore support strike never uses, plus go-funk,
osv-schema, and stringset, purely to call two converter functions. osv-scalibr
is therefore not used. Instead, strike parses `package-lock.json` and dpkg
`status` in strike-owned native parsers (lockfiles and the dpkg status database
are simple, documented formats; "a little copying is better than a little
dependency", with the option to lift an audited parser file under its
Apache-2.0 license with attribution rather than import a module), and renders
CycloneDX via `cyclonedx-go` and SPDX 2.3 via `spdx/tools-golang` (its model and
JSON sub-packages only, avoiding the RDF and YAML dependencies). The conformant
serialization stays in those libraries; strike owns only the field mapping.
`cyclonedx-go` therefore remains a direct dependency, revising the original note
above that it would become transitive; `spdx/tools-golang` and
`package-url/packageurl-go` are added as focused direct dependencies. The
modular repo-manifest collector `git-pkgs/manifests` was evaluated and deferred:
it targets declared repo manifests and lockfiles rather than an image's
installed-package state, does not cover the dpkg installed-package database, and
is pre-1.0 single-maintainer -- revisit only if strike moves toward broad
repo-source multi-ecosystem cataloging.

### D2 -- Signing is keyless, driven in-process

Identity is gated by hardware at the IdP, not by holding a key. A FIDO2 token
enforces user verification at the OIDC provider via WebAuthn; strike is
FIDO2-agnostic, exactly as cosign is. The keyless chain is intact: OIDC ->
ephemeral key -> Fulcio short-lived certificate -> DSSE -> Rekor v2. The only
durable secret in the chain is the OIDC identity.

strike drives this chain in-process as Go libraries, never by spawning the
cosign CLI (no exec, no shell). Per the keyless import-surface spike, the
composed library set covers the full flow -- sigstore-go/pkg/sign (ephemeral
keypair, Fulcio, DSSE, Rekor v2 upload, bundle assembly), sigstore/pkg/oauthflow
(the interactive OIDC flow), and go-containerregistry (referrer attach, already
a strike dependency). Rekor v2 (tile / Tessera) is supported in-process by these
libraries. The composed set is chosen over importing cosign-as-a-library: it
covers the same flow at roughly one third the binary size and without the cloud
KMS provider clusters (AWS, Azure, GCP) that cosign-as-a-library drags in
through its CLI option and timestamp paths.

### D3 -- Attestations are cosign-compatible OCI referrers, layered by trust

ADR-037 establishes two trust layers toward the engine -- V (verify or observe;
the no-false-positive layer, produced or independently re-verified by the
control plane) and E (engine-dependent; exposed to a silent false negative).
strike's attestation carries these two plus an informational bucket that never
gates a verification. All three are realized as separate attestations in the
standard ecosystem, so the layer boundary is physical rather than a convention
inside one signature:

- The sealed (V) layer is a standard SLSA Provenance v1 predicate:
  externalParameters (the lane plus its digest-pinned inputs, including the
  declared OIDC identity), resolvedDependencies (control-plane-computed input
  digests), runDetails.builder (the control-plane identity). Verifiable by any
  SLSA verifier and by `cosign verify-attestation`.
- The engine_dependent (E) layer is a separate predicate of a strike-defined
  type (for example `strike.dev/predicates/engine-context/v1`), co-attached as
  its own referrer: engine identity, transport fingerprint, engine-reported
  actions. Because it is physically separate, the sealed provenance verifies
  without trusting any engine-relayed claim.
- The informational layer rides as byproducts -- signed, but never gating a
  verification exit.

Per-layer verification exit is expressed as which predicates `strike verify`
requires per trust mode: under engine trust it requires both V and E; under
no-engine-trust it requires only V; informational never gates. The L3-versus-L2+
distinction surfaces precisely here -- whether the E predicate is trusted -- and
that single switch gates exactly the two L3-only properties (build isolation and
complete externalParameters). ADR-013 is retained: sealed.rekor is not part of
the signed payload and is stripped before signature verification.

### D4 -- The control plane owns the registry push

strike pushes the assembled image to the registry itself, via
go-containerregistry remote.Write. The engine may still pull by digest for now,
but it never pushes. Signing and referrer attach happen after the
control-plane push, on the registry digest, so the signature covers the artifact
as it exists in the registry. The payload on the wire is what is attested.

### D5 -- Lane-wide OIDC identity, pinned, flowing into the attestation

A new CUE schema element declares the signing identity at lane scope -- the
keyless successor to the SignConfig that was removed earlier:

```cue
#OIDCConfig: {
	@go(OIDCConfig)
	issuer:    string @go(Issuer)     // iss / issuer-url; local IdP for testing, real IdP later, config only
	client_id: string @go(ClientID)   // aud
	identity:  string @go(Identity)   // expected SAN subject Fulcio writes into the cert
	trust:     #TLSTrust @go(Trust)  // pin the IdP endpoints (cert fingerprint / CA bundle), like resolver.trust
}
```

attached to the lane as a required field, `oidc: #OIDCConfig @go(OIDC)`. It is
defined in CUE first; the Go type is generated.

The IdP is a declared peer: `trust` pins its endpoints with the existing
`#TLSTrust` trust-anchor type, so a man-in-the-middle IdP cannot mint tokens
strike will trust. The declared issuer and identity become a sealed claim in the
provenance, and `strike verify` cross-checks the Fulcio certificate against them:
cert issuer equals declared issuer, and cert SAN equals declared identity. The
identity is pinned by the lane, recorded in the attestation, and asserted at
verify -- and because the lane config is control-plane-controlled, this holds
without engine trust. JWKS / token-signing-key pinning is a deeper option
deferred for now; the endpoint anchor plus issuer and identity suffice for the
first cut.

## Consequences

- The original SBOM crash class is eliminated at its root: the buildinfo path is
  removed, not patched. The SBOM now describes the artifact, with a correct
  subject and real components, in two formats.
- strike's trusted binary grows by the measured marginal surfaces only. The
  scalibr-minimal surface prunes the container-runtime, vuln, TUI, weak-credential
  and resolution clusters; the B-walker additionally sheds the disk-image
  cluster. The keyless-composed surface prunes all cloud KMS clusters. Both were
  measured, not estimated.
- Output attestations are independently verifiable offline by cosign and SLSA
  tooling, without contacting strike or the original engine.
- SPDX is produced first-class alongside CycloneDX.
- `strike verify` is now well-defined by this ADR: referrers plus Rekor
  inclusion plus SLSA and SBOM predicate validation plus the issuer/identity
  cross-check, with per-layer exit driven by trust mode. This unblocks the
  verify track.
- The new `#OIDCConfig` element and the removal of the buildinfo SBOM path are
  breaking changes; acceptable pre-beta.
- Commit-to-artifact provenance for the npm ecosystem (the end-to-end target)
  remains future work. Cataloging gives the component inventory now; verifying
  npm's own sigstore provenance during cataloging or verify is a later layer,
  for which this architecture leaves room.

## Supersedes and extends

- Supersedes ADR-019's SBOM generation mechanism (Go buildinfo -> control-plane
  cataloging of the sealed image) and revises its signing (operator-held key ->
  keyless) and its format stance (CycloneDX-only generation -> CycloneDX and
  SPDX). Retains ADR-019's referrer attachment (OCI 1.1 referrer primary, cosign
  tag fallback) and its base-image SBOM resolution order.
- Extends ADR-037 (two trust layers toward the engine) by realizing its V and E
  layers, plus strike's non-gating informational bucket, as standard SLSA
  provenance and co-attached cosign referrers.
- Retains ADR-013 (sealed.rekor stripped before signature verification).
- Reintroduces, in keyless form as `#OIDCConfig`, the lane-level signing
  configuration removed with SignConfig.

## Principles

- Runtime is attested -- the SBOM and the runtime context are signed and logged,
  layered by what the control plane can independently establish.
- Identity is asymmetric, and the architecture is identity-first -- the signing
  identity (OIDC / Fulcio), the peer identities (trust anchors, now including the
  IdP), and the artifact identity (digest) are the load-bearing elements; there
  is no long-lived key to hold.
- Peers are declared -- the IdP is a declared peer with a pinned trust anchor.
- External references are digest-pinned -- the signature covers the registry
  digest the control plane pushed.
- Reproducibility is enforced -- the SBOM document is canonicalized.
- Code is liability -- the cataloger and the signing stack are composed from the
  leanest audited libraries that cover the task, measured by spike; the walker is
  chosen over a dependency.
- No exec -- the keyless flow runs in-process as libraries, never by spawning a
  CLI.
