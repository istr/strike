// specs/trust-layers.cue
//
// Trust-layer map -- the single source of truth for the V / E / informational
// classification of every attested field (the soundness note's three-way split).
//
// WHY THIS FILE EXISTS. The classification is one unit of meaning; per the
// "Meaning is single-sourced" principle it has exactly one home. attestation.cue
// (internal collect-model) and predicate.cue (published statements) are two
// PROJECTIONS of this map. A conformance test asserts both agree with it. Do not
// restate the classification in prose anywhere -- link to this file instead.
//
// HOW THE LAYER IS DECIDED. The layer is NOT assigned per field. Each field states
// only its `provenance` -- who produced the bytes, and for external facts whether
// CP verified them -- and its `layer` is DERIVED from that provenance through the
// fixed rule table `layerOf` below. This makes "no E-link recorded as a V-link"
// structural: an author cannot promote a fact by relabelling it, only by changing a
// provenance the conformance test cross-checks against the schema. The rules and
// their two asymmetries (verification-not-trust admits to V; declaration hardens an
// observation but never confers a layer) are stated in
// ATTESTATION-SOUNDNESS-AND-THE-TRUST-BOUNDARY.md "Decision procedure".
//
// EXPORT. `make specs` exports this to specs/trust-layers.json for external
// verifiers and policy engines (now including the layerOf rule table). It is DATA,
// not a JSON Schema.

package trustlayers

#TrustLayer: "V" | "E" | "informational"

// Where a field surfaces in the published projection. "bundle" = carried in the
// Sigstore bundle, never in a predicate payload (ADR-013). "none" = not emitted.
#PublishedIn: "slsa-provenance" | "engine-context" | "informational" | "bundle" | "none"

// #Provenance -- the SOLE input to the layer decision: who produced a fact's bytes
// and, for external facts, whether CP verified them. Exactly one kind holds per
// fact; the layer is a consequence (layerOf), never stated by hand.
//
//   cpSealed             CP computes/holds canonical, reproducible bytes (declared
//                        lane scalars, CP-computed digests, the in-process SBOM).
//                        A verifier recomputes them; sound without engine trust.
//   cpObserved           CP observed AND verified an external party's identity
//                        (front-observed, pinned/checked TLS: a declared peer, the
//                        resolver, the engine connection). Verification is what
//                        admits an external fact to V; mere trust does not.
//   engineChainAssertion The engine asserts a source-to-deploy chain fact CP relies
//                        on under trust(E) (peerAttribution). Sound only under E.
//   engineSelfReport     The engine asserts a fact about ITSELF (version, rootless
//                        mode). Participates in no chain claim; no trust claim.
//   containerProduced    Bytes produced by the untrusted container and engine-
//                        relayed (state-capture digests, container-written
//                        provenance). CP's hash transports them; it does not lift
//                        them out of the container-asserted class.
//   hostAsserted         A value CP reads from the host under a bare trust
//                        assumption, of unknown origin and carrying no cryptographic
//                        claim, superseded by a canonical source (the deploy
//                        wall-clock; Rekor integratedTime is canonical, per
//                        SECURITY.md "Wallclock trust"). The kind also fits
//                        host-environment facts about the attesting process --
//                        kernel, distro, uid -- were any ever recorded (none are
//                        today; YAGNI).
#Provenance: "cpSealed" | "cpObserved" | "engineChainAssertion" | "engineSelfReport" | "containerProduced" | "hostAsserted"

// layerOf -- the decision procedure AS DATA: the one place the V / E /
// informational rules are encoded. Read it as the rule table:
//   V             <- cpSealed | cpObserved
//   E             <- engineChainAssertion
//   informational <- engineSelfReport | containerProduced | hostAsserted
// A field's `layer` is layerOf[its provenance]. Declaration is NOT a key here, so a
// declared-but-unobserved fact cannot reach V by construction. The pattern
// constraint pins keys to #Provenance and values to #TrustLayer; the conformance
// test pins the table to the rules above.
layerOf: [#Provenance]: #TrustLayer
layerOf: {
	cpSealed:             "V"
	cpObserved:           "V"
	engineChainAssertion: "E"
	engineSelfReport:     "informational"
	containerProduced:    "informational"
	hostAsserted:         "informational"
}

#Entry: {
	// provenance -- the producer/verification kind; the SOLE input to `layer`.
	provenance: #Provenance
	// layer -- DERIVED from provenance via layerOf; never assigned by hand.
	layer: #TrustLayer & layerOf[provenance]
	// hardenedByDeclaration -- true iff the lane declares an expected value for this
	// fact that CP checks against its observation at runtime, hard-failing on
	// mismatch. Only a cpObserved fact can be hardened (you cannot check an
	// observation never made); the conformance test enforces that. Records today's
	// reality: the pinned resolver and the dialed peers are hardened by the transport
	// verifier; the engine connection is observed but NOT yet hardened (no declared-
	// expected engine identity -- the engine-transport arc closes this), so its row
	// is deliberately false and the gap is machine-visible.
	hardenedByDeclaration: bool | *false
	internal:  string       // path in attestation.cue's #Attestation, or "-" if not in the collect-model
	published: #PublishedIn // statement in predicate.cue that carries it
	rationale: string       // one-line soundness rationale (human context; not load-bearing)
}

// Section anchors: each top-level section of #Attestation, the published statement
// that mirrors it, and the layer the whole section carries. The simplest
// conformance check is "every field of a section has the section's layer"; the
// per-field map below additionally pins each field's published home.
sections: [string]: {layer: #TrustLayer, statement: #PublishedIn}
sections: {
	sealed: {layer: "V", statement: "slsa-provenance"}
	engineDependent: {layer: "E", statement: "engine-context"}
	informational: {layer: "informational", statement: "informational"}
}

// Per-field map. Key = stable logical field id (path-independent), so the same fact
// keys the same row regardless of where each schema nests it. (The field whose id
// is "provenance" carries container-written records; its key coincides with the
// #Entry attribute name by chance, not by relation.)
fields: [string]: #Entry
fields: {
	// ---- V: CP-sealed canonical bytes (cpSealed) ----
	laneId: {provenance: "cpSealed", internal: "sealed.laneId", published: "slsa-provenance", rationale: "declared lane scalar"}
	laneDigest: {provenance: "cpSealed", internal: "sealed.laneDigest", published: "slsa-provenance", rationale: "CP hashes the lane file itself (data CP holds)"}
	target: {provenance: "cpSealed", internal: "sealed.target", published: "slsa-provenance", rationale: "declared, lane-anchored"}
	oidc: {provenance: "cpSealed", internal: "-", published: "slsa-provenance", rationale: "declared signing identity; injected at sign time from lane OIDC config (absent from the collect-model)"}
	peers: {provenance: "cpSealed", internal: "sealed.peers", published: "slsa-provenance", rationale: "declared, lane-anchored"}

	// ---- V: CP-verified external observations (cpObserved) ----
	resolver: {provenance: "cpObserved", hardenedByDeclaration: true, internal: "sealed.resolver", published: "slsa-provenance", rationale: "CP-observed resolver TLS identity at the pre-flight handshake (front-observed), pinned per the lane"}
	engine: {provenance: "cpObserved", internal: "sealed.engine", published: "slsa-provenance", rationale: "CP-observed engine connection facts (#EngineConnection); NOT the self-report. Observed but not yet declaration-hardened"}
	observedPeers: {provenance: "cpObserved", hardenedByDeclaration: true, internal: "sealed.observedPeers", published: "slsa-provenance", rationale: "CP-validated peer identity, dialed and verified per the lane spec (front-observed)"}

	// ---- V: CP-sealed artifact outputs (cpSealed) ----
	artifactDigest: {provenance: "cpSealed", internal: "sealed.artifacts[].digest", published: "slsa-provenance", rationale: "published artifact digest, consumer-dereferenceable by D (C3); -> subject / resolvedDependencies"}
	artifactSBOM: {provenance: "cpSealed", internal: "sealed.artifacts[].sbom", published: "slsa-provenance", rationale: "SBOM produced in-process from bytes CP holds; document also emitted as its own OCI referrer"}

	// ---- E: engine chain assertion (engineChainAssertion) ----
	peerAttribution: {provenance: "engineChainAssertion", internal: "engineDependent.peerAttribution", published: "engine-context", rationale: "engine-asserted step<->peer binding; not sound against a malicious engine (C1)"}

	// ---- informational: no trust claim ----
	timestamp: {provenance: "hostAsserted", internal: "informational.timestamp", published: "informational", rationale: "host wall-clock at deploy start, trusted not verified; Rekor integratedTime is canonical"}
	engineMetadata: {provenance: "engineSelfReport", internal: "informational.engineMetadata", published: "informational", rationale: "engine self-report (version, rootless); does not participate in the source-to-deploy chain"}
	preStateDigest: {provenance: "containerProduced", internal: "informational.preStateDigest", published: "informational", rationale: "container-produced, engine-relayed; CP's hash transports the bytes, it does not lift them out of the container-asserted class"}
	postStateDigest: {provenance: "containerProduced", internal: "informational.postStateDigest", published: "informational", rationale: "symmetric to preStateDigest"}
	provenance: {provenance: "containerProduced", internal: "informational.provenance", published: "informational", rationale: "container-written source-provenance records, engine-relayed; audit/IoC only, never gating"}
}
