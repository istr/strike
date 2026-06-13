// strike output attestation predicates (ADR-040 D3).
//
// These are the standard-ecosystem attestations strike SIGNS and publishes,
// distinct from the internal #Attestation collect-model in attestation.cue
// (ADR-039 produce-then-collect). The projection internal -> these shapes runs
// at sign time (a later instruction); this file defines the output shapes only.
//
// The layer boundary is physical (ADR-037, ADR-040 D3): the sealed (V) layer
// is a standard SLSA Provenance v1 statement; the engineDependent (E) layer
// is a strike-defined engine-context statement; the informational layer is a
// strike-defined informational statement. Each is signed as its own referrer.
//
// Rekor inclusion lives in the sigstore bundle, never in a predicate payload
// (ADR-013 satisfied structurally): no predicate here carries a rekor field.
//
// Available here without import: #Timestamp, #ObservedPeer, #ResolverRecord,
// #EngineConnection, and #EngineMetadata are defined in this package (deploy)
// in attestation.cue; #Digest, #DeployTarget, #Peer, and #ProvenanceRecord are
// defined in package lane and re-exported into deploy via artifact.cue
// (#ProvenanceRecord lives in source-provenance.cue).

package deploy

// ---------------------------------------------------------------------------
// in-toto attestation framework primitives (in-toto Statement v1)
// ---------------------------------------------------------------------------

// #DigestSet is an in-toto DigestSet. Typed to the algorithms strike emits
// rather than an open map (map[string]string is prohibited for structured
// data; a typed subset is a conformant DigestSet instance). Image subjects
// carry sha256; git resolved-dependencies carry gitCommit.
#DigestSet: {
	sha256?:    =~"^[a-f0-9]{64}$"
	sha512?:    =~"^[a-f0-9]{128}$"
	gitCommit?: =~"^[a-f0-9]{40}$"
}

// #ResourceDescriptor is the in-toto ResourceDescriptor. strike emits only the
// fields it uses; content and annotations are omitted deliberately (optional in
// the spec, and an open annotations object would reintroduce a map).
#ResourceDescriptor: {
	name?:             string
	uri?:              string
	digest?:           #DigestSet
	mediaType?:        string
	downloadLocation?: string
}

// #Subject is one in-toto statement subject: a deployed artifact.
#Subject: {
	name:   string
	digest: #DigestSet
}

// ---------------------------------------------------------------------------
// Sealed (Layer V): standard SLSA Provenance v1 statement.
// predicateType https://slsa.dev/provenance/v1
// "_type" is quoted: an unquoted _type would be a CUE hidden field and would
// not serialize.
// ---------------------------------------------------------------------------

#SLSAProvenanceStatement: {
	"_type": "https://in-toto.io/Statement/v1"
	subject: [...#Subject]
	predicateType: "https://slsa.dev/provenance/v1"
	predicate:     #SLSAProvenancePredicate
}

#SLSAProvenancePredicate: {
	buildDefinition: #SLSABuildDefinition
	runDetails:      #SLSARunDetails
}

#SLSABuildDefinition: {
	buildType:          "https://istr.dev/strike/buildtypes/lane/v1"
	externalParameters: #StrikeExternalParameters
	resolvedDependencies?: [...#ResourceDescriptor]
}

// #StrikeExternalParameters occupies SLSA's open externalParameters slot with
// strike's typed Layer-V facts (Fork D). The lane and its anchors, the declared
// OIDC identity, the declared peers, and the peer / resolver / engine
// identities the control plane observed and validated against the declared
// anchors -- all control-plane-established, sound without engine trust.
#StrikeExternalParameters: {
	laneId:     =~"^[a-z0-9][a-z0-9-]{0,62}$"
	laneDigest: #Digest | ""
	target:      #DeployTarget
	oidc:        #ProvenanceOIDC
	peers: [Step=string]: [...#Peer]
	observedPeers?: [Endpoint=string]: #ObservedPeer
	resolver?: #ResolverRecord
	engine?:   #EngineConnection
}

// #ProvenanceOIDC is the declared signing identity carried into the sealed
// provenance (ADR-040 D5). issuer and identity are the cross-check targets
// strike verify asserts against the Fulcio certificate. The trust anchor is
// not repeated: it is lane config, not an attested output fact.
#ProvenanceOIDC: {
	issuer:   string
	identity: string
}

#SLSARunDetails: {
	builder:   #SLSABuilder
	metadata?: #SLSABuildMetadata
	byproducts?: [...#ResourceDescriptor]
}

// #SLSABuilder.id is the control-plane builder identity. builderDependencies
// and version are optional in the spec and omitted here (the open version map
// would violate the no-map rule); add them only on a concrete need.
#SLSABuilder: {
	id: string
}

// #SLSABuildMetadata carries only reproducible fields. Wall-clock timestamps
// are NOT placed in the sealed provenance: ADR-037 holds Rekor integratedTime
// as canonical and treats wall-clock as informational, and reproducibility
// (byte-identical sealed output for byte-identical inputs) forbids a live clock
// here. invocationId is present for parity, populated only with a reproducible
// value if any.
#SLSABuildMetadata: {
	invocationId?: string
}

// ---------------------------------------------------------------------------
// Engine-dependent (Layer E): strike-defined engine-context statement.
// predicateType https://istr.dev/strike/predicates/engine-context/v1
// ---------------------------------------------------------------------------

#EngineContextStatement: {
	"_type": "https://in-toto.io/Statement/v1"
	subject: [...#Subject]
	predicateType: "https://istr.dev/strike/predicates/engine-context/v1"
	predicate:     #EngineContextPredicate
}

// #EngineContextPredicate carries the Layer-E claims only: the engine's
// self-reported metadata (engineMetadata) and the engine-asserted attribution
// of mediated connections to steps (peerAttribution). The control-plane-
// observed engine connection (#EngineConnection) is NOT here -- it is Layer V
// and rides in the sealed provenance's externalParameters (Fork C).
#EngineContextPredicate: {
	engineMetadata?: #EngineMetadata
	peerAttribution?: [Step=string]: [...string]
}

// ---------------------------------------------------------------------------
// Informational: strike-defined informational statement.
// predicateType https://istr.dev/strike/predicates/informational/v1
// Signed byproducts that never gate a verification exit (ADR-040 D3): the
// deploy wall-clock, the pre/post-state digests, and the container-asserted
// provenance. Carries no trust claim; a verifier discriminates it by
// predicateType and never lets its contents affect the exit (ADR-037).
// ---------------------------------------------------------------------------

#InformationalStatement: {
	"_type": "https://in-toto.io/Statement/v1"
	subject: [...#Subject]
	predicateType: "https://istr.dev/strike/predicates/informational/v1"
	predicate:     #InformationalPredicate
}

#InformationalPredicate: {
	// timestamp is CP's wall-clock at deploy start. Informational, not the
	// canonical time: Rekor integratedTime is canonical (ADR-037). This is the
	// one output statement that carries a wall-clock; the sealed provenance is
	// reproducible and omits it.
	timestamp?: #Timestamp

	// preStateDigest / postStateDigest are CP's canonical SHA-256 digests of
	// the pre/post-deploy state captures. The bytes were produced by the
	// (untrusted) capture container and engine-relayed; CP's hash transports
	// them, it does not lift them out of the container-asserted class.
	preStateDigest:  #Digest
	postStateDigest: #Digest

	// provenance collects validated provenance records from transitive
	// predecessor steps; each is container-written at step exit and
	// engine-relayed. Recorded for audit and IoC, never gating.
	provenance: [...#ProvenanceRecord]
}
