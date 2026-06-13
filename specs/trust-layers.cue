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
// SOURCE OF THE CLASSIFICATION. Derived from
// ATTESTATION-SOUNDNESS-AND-THE-TRUST-BOUNDARY.md:
//   V             Sound to any verifier without engine trust -- CP-sealed or
//                 CP-observed. Declared lane scalars, published artifact
//                 digest/signature/SBOM, front-observed peer/resolver/engine
//                 identity, Rekor-anchored material.
//   E             Sound only under trust(E). Engine-asserted binding of a network
//                 action to a step (C1 attribution); not sound against a malicious
//                 engine.
//   informational No trust claim. Container-asserted content (untrusted subject,
//                 regardless of engine trust) and engine self-reports that do not
//                 participate in the source-to-deploy chain.
//
// THE DISCRIMINATOR. Who produced the bytes: CP-produced or CP-observed -> V;
// engine-asserted -> E; container-produced -> informational (engine trust does
// not lift it, because the container is a separate untrusted subject).
//
// EXPORT. `make specs` exports this to specs/trust-layers.json for external
// verifiers and policy engines. It is DATA, not a JSON Schema.

package trustlayers

#TrustLayer: "V" | "E" | "informational"

// Where a field surfaces in the published projection. "bundle" = carried in the
// Sigstore bundle, never in a predicate payload (ADR-013). "none" = not emitted.
#PublishedIn: "slsa-provenance" | "engine-context" | "informational" | "bundle" | "none"

#Entry: {
	layer:     #TrustLayer
	internal:  string       // path in attestation.cue's #Attestation, or "-" if not in the collect-model
	published: #PublishedIn // statement in predicate.cue that carries it
	basis:     string       // one-line soundness rationale
}

// Section anchors: each top-level section of #Attestation, the published
// statement that mirrors it, and the layer the whole section carries. The
// simplest conformance check is "every field of a section has the section's
// layer"; the per-field map below additionally pins each field's published home.
sections: [string]: {layer: #TrustLayer, statement: #PublishedIn}
sections: {
	sealed: {layer: "V", statement: "slsa-provenance"}
	engineDependent: {layer: "E", statement: "engine-context"}
	informational: {layer: "informational", statement: "informational"}
}

// Per-field map. Key = stable logical field id (path-independent), so the same
// fact keys the same row regardless of where each schema nests it.
fields: [string]: #Entry
fields: {
	// ---- Layer V: CP-sealed or CP-observed; sound without engine trust ----
	laneId: {layer: "V", internal: "sealed.laneId", published: "slsa-provenance", basis: "declared lane scalar"}
	laneDigest: {layer: "V", internal: "sealed.laneDigest", published: "slsa-provenance", basis: "CP hashes the lane file itself (data CP holds, cat. 1)"}
	target: {layer: "V", internal: "sealed.target", published: "slsa-provenance", basis: "declared, lane-anchored"}
	oidc: {layer: "V", internal: "-", published: "slsa-provenance", basis: "declared signing identity; injected at sign time from lane OIDC config (absent from the collect-model)"}
	peers: {layer: "V", internal: "sealed.peers", published: "slsa-provenance", basis: "declared, lane-anchored"}
	resolver: {layer: "V", internal: "sealed.resolver", published: "slsa-provenance", basis: "CP-observed resolver TLS identity at the pre-flight handshake (front-observed)"}
	engine: {layer: "V", internal: "sealed.engine", published: "slsa-provenance", basis: "CP-observed/controlled engine connection facts (#EngineConnection); NOT the self-report"}
	observedPeers: {layer: "V", internal: "sealed.observedPeers", published: "slsa-provenance", basis: "CP-validated peer identity, dialed per the lane spec (front-observed)"}

	artifactDigest: {layer: "V", internal: "sealed.artifacts[].digest", published: "slsa-provenance", basis: "published artifact digest, consumer-dereferenceable by D (C3); -> subject / resolvedDependencies"}
	artifactSBOM: {layer: "V", internal: "sealed.artifacts[].sbom", published: "slsa-provenance", basis: "SBOM produced in-process from bytes CP holds (sealed/V per ARCHITECTURE); document also emitted as its own OCI referrer"}
	artifactSignature: {layer: "V", internal: "sealed.artifacts[].signature", published: "bundle", basis: "CP-produced signature; verification material rides in the Sigstore bundle"}
	artifactRekor: {layer: "V", internal: "sealed.artifacts[].rekor", published: "bundle", basis: "Rekor-anchored; verified against the Rekor public key CP holds; kept out of the predicate payload (ADR-013)"}

	// ---- Layer E: engine-asserted; sound only under trust(E) ----
	peerAttribution: {layer: "E", internal: "engineDependent.peerAttribution", published: "engine-context", basis: "engine-asserted step<->peer binding; not sound against a malicious engine (C1)"}

	// ---- informational: no trust claim (container-asserted or out-of-chain) ----
	timestamp: {layer: "informational", internal: "informational.timestamp", published: "informational", basis: "CP wall-clock at deploy start; Rekor integratedTime is canonical"}
	engineMetadata: {layer: "informational", internal: "informational.engineMetadata", published: "informational", basis: "engine self-report (version, rootless); does not participate in the source-to-deploy chain"}
	preStateDigest: {layer: "informational", internal: "informational.preStateDigest", published: "informational", basis: "container-produced, engine-relayed; CP's hash transports the bytes, it does not lift them out of the container-asserted class"}
	postStateDigest: {layer: "informational", internal: "informational.postStateDigest", published: "informational", basis: "symmetric to preStateDigest"}
	provenance: {layer: "informational", internal: "informational.provenance", published: "informational", basis: "container-written source-provenance records, engine-relayed; audit/IoC only, never gating"}
}

// KNOWN DIVERGENCE (kept as a comment, not a field, so a conformance test cannot
// whitelist it as an expected pass). This map is canonical; the schemas conform
// to it, not the reverse:
//
//   engineMetadata -- predicate.cue currently files this under
//   #EngineContextPredicate (Layer E). Canonical layer above is `informational`
//   (soundness note: engine self-reports do not participate in the
//   source-to-deploy chain). FIX: move engineMetadata into the informational
//   statement (#InformationalPredicate) in predicate.cue. The Stage-1 conformance
//   test is expected to fail on this row until the move is made.
