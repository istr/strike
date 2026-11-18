// strike output attestation predicates (ADR-040 D3).
//
// These are the standard-ecosystem attestations strike SIGNS and publishes,
// distinct from the internal #Attestation collect-model in attestation.cue
// (ADR-039 produce-then-collect). The projection internal -> these shapes runs
// at sign time; this file defines the output shapes only.
//
// The layer boundary is physical (ADR-037, ADR-040 D3): the sealed (V) layer
// is a standard SLSA Provenance v1 statement; the engineDependent (E) layer
// is a strike-defined engine-context statement; the informational layer is a
// strike-defined informational statement. Each is signed as its own referrer.
//
// The image SBOM is published as a fourth statement, #SBOMStatement, which is
// none of the layer statements: its predicate is the CycloneDX document
// (ADR-059 D2). It is signed and attached like the three.
//
// Rekor inclusion lives in the sigstore bundle, never in a predicate payload
// (ADR-013 satisfied structurally): no predicate here carries a rekor field.
//
// Shared types named here resolve two ways: #ObservedPeer,
// #ResolverRecord, #EngineMetadata, and #Subject are defined in this attest
// package (attestation.cue and this file); #Timestamp is from the primitive
// package; the declared endpoints and the other endpoint types are named
// qualified through the endpoint import.

package attest

import (
	"github.com/istr/strike/contract/endpoint"
	"github.com/istr/strike/contract/primitive"
	provenancepkg "github.com/istr/strike/contract/provenance"
)

// ---------------------------------------------------------------------------
// in-toto attestation framework primitives (in-toto Statement v1)
// ---------------------------------------------------------------------------

// #DigestSet is an in-toto DigestSet. Typed to the algorithms strike emits
// rather than an open map (map[string]string is prohibited for structured
// data; a typed subset is a conformant DigestSet instance). Image subjects
// carry sha256; git resolved-dependencies carry gitCommit (40-hex SHA-1 or
// 64-hex SHA-256, matching the source-provenance commit width).
#DigestSet: {
	sha256?:    primitive.#Sha256   @go(SHA256)
	sha512?:    =~"^[a-f0-9]{128}$" @go(SHA512)
	gitCommit?: primitive.#GitCommit
}

// #ResourceDescriptor is the in-toto ResourceDescriptor. strike emits only the
// fields it uses; content and annotations are omitted deliberately (optional in
// the spec, and an open annotations object would reintroduce a map).
#ResourceDescriptor: {
	name?:             string
	uri?:              string     @go(URI)
	digest?:           #DigestSet @go(Digest,optional=nillable)
	mediaType?:        string
	downloadLocation?: string
}

// #Subject is one in-toto statement subject: a deployed artifact. It is an
// in-toto ResourceDescriptor (reused, not re-declared) with name and digest
// required, since a deployed artifact must be named and content-addressed.
#Subject: #ResourceDescriptor & {
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
	"_type": "https://in-toto.io/Statement/v1" @go(Type)
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
// strike's typed Layer-V facts (ADR-040 D3). The lane and its anchors, the
// declared OIDC identity, the declared peers, and the peer / resolver / engine
// identities the control plane observed and validated against the declared
// anchors -- all control-plane-established, sound without engine trust.
#StrikeExternalParameters: {
	laneId:     primitive.#Identifier @go(LaneID)
	laneDigest: primitive.#Digest
	oidc:       #ProvenanceOIDC @go(OIDC)
	peers: {
		[ID=primitive.#Identifier]: [...endpoint.#Endpoint]
	} @go(Peers,type=map[primitive.Identifier][]endpoint.Endpoint)
	observedPeers?: {
		[Endpoint=endpoint.#Authority]: #ObservedPeer
	} @go(ObservedPeers,type=map[endpoint.Authority]ObservedPeer)
	resolver: #ResolverRecord
	engine?:  endpoint.#Engine

	// pushed mirrors sealed.pushed: the registry address of the artifact this
	// statement's subject names, so a verifier holding only the statement can
	// dereference it.
	pushed?: #PushedArtifact @go(Pushed,optional=nillable)
}

// #ProvenanceOIDC is the declared signing identity carried into the sealed
// provenance (ADR-040 D5). issuer and identity are the cross-check targets
// strike verify asserts against the Fulcio certificate. The trust anchor is
// not repeated: it is lane config, not an attested output fact.
#ProvenanceOIDC: {
	issuer:   endpoint.#URL          @go(Issuer,type=endpoint.Address)
	identity: primitive.#StringOrURI @go(Identity)
}

// #SLSARunDetails.byproducts lists what the sealing act generated beside its
// subject, sorted by name (ADR-059 D1): the produced identity of every
// artifact, and every SBOM document of the deploy with its media type and the
// sha256 of its bytes.
#SLSARunDetails: {
	builder:   #SLSABuilder
	metadata?: #SLSABuildMetadata @go(Metadata,optional=nillable)
	byproducts?: [...#ResourceDescriptor & {name: #ByproductName}]
}

// #ByproductName is the name grammar of a byproduct (ADR-059 D1). The bare
// name of an artifacts entry names the produced identity of that artifact. A
// document is named by the entry it belongs to and its level: "<artifact>/sbom"
// for the document of a file or directory region, "<artifact>/sbom/top-level"
// and "<artifact>/sbom/delivery-item" for the documents of the image. The
// top-level document is the one the SBOM statement carries as its predicate
// (#SBOMStatement), so the sealed statement alone tells a verifier which
// statement to expect.
#ByproductName: =~"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(/sbom(/(top-level|delivery-item))?)?$" @go(-)

// #SLSABuilder.id is the control-plane builder identity. builderDependencies
// is optional in the spec and omitted here; add it only on a concrete need.
// version is optional in the spec and required here (ADR-060 D5). The spec
// defines it as an open map, which the no-map rule excludes, so it is a
// closed struct with the one key.
#SLSABuilder: {
	id: string @go(ID)
	// version names the strike that produced the statement.
	version: #SLSABuilderVersion
}

// #SLSABuilderVersion carries the version of the control plane and nothing
// else, no date and no commit (ADR-060 D5).
#SLSABuilderVersion: {
	// strike is the version the source of the control plane states.
	strike: primitive.#SemVer
}

// #SLSABuildMetadata carries only reproducible fields. Wall-clock timestamps
// are NOT placed in the sealed provenance: the RFC3161 TSA token is the trusted
// time (ADR-040) and wall-clock is informational, and reproducibility
// (byte-identical sealed output for byte-identical inputs) forbids a live clock
// here. invocationId is present for parity, populated only with a reproducible
// value if any.
#SLSABuildMetadata: {
	invocationId?: string @go(InvocationID)
}

// ---------------------------------------------------------------------------
// Engine-dependent (Layer E): strike-defined engine-context statement.
// predicateType https://istr.dev/strike/predicates/engine-context/v1
// ---------------------------------------------------------------------------

#EngineContextStatement: {
	"_type": "https://in-toto.io/Statement/v1" @go(Type)
	subject: [...#Subject]
	predicateType: "https://istr.dev/strike/predicates/engine-context/v1"
	predicate:     #EngineContextPredicate
}

// #EngineContextPredicate carries the Layer-E claim only: the engine-asserted
// attribution of mediated connections to steps (peerAttribution). The
// control-plane-observed engine connection (#Engine) is NOT here --
// it is Layer V and rides in the sealed provenance's externalParameters
// (ADR-057 D10). The engine's self-report (engineMetadata) is NOT here
// either -- it carries no trust claim and lives in the informational
// statement.
#EngineContextPredicate: {
	peerAttribution?: {
		[ID=primitive.#Identifier]: [...endpoint.#Authority]
	} @go(PeerAttribution,type=map[primitive.Identifier][]endpoint.Authority)
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
	"_type": "https://in-toto.io/Statement/v1" @go(Type)
	subject: [...#Subject]
	predicateType: "https://istr.dev/strike/predicates/informational/v1"
	predicate:     #InformationalPredicate
}

#InformationalPredicate: {
	// timestamp is CP's wall-clock at deploy start. Informational, not the
	// trusted time: the RFC3161 TSA token is the trusted time (ADR-040). This is
	// the one output statement that carries a wall-clock; the sealed provenance is
	// reproducible and omits it.
	timestamp?: primitive.#Timestamp

	// preStateDigest / postStateDigest are CP's canonical SHA-256 digests of
	// the pre/post-deploy state captures. The bytes were produced by the
	// (untrusted) capture container and engine-relayed; CP's hash transports
	// them, it does not lift them out of the container-asserted class.
	preStateDigest:  primitive.#Digest
	postStateDigest: primitive.#Digest

	// provenance collects validated provenance records from transitive
	// predecessor steps; each is container-written at step exit and
	// engine-relayed. Recorded for audit and IoC, never gating.
	provenance: [...provenancepkg.#Record]

	// engineMetadata is the engine's self-report about itself (version, rootless
	// mode). It carries no trust claim -- the engine asserting facts about
	// itself participates in no source-to-deploy claim -- so it is
	// informational, not an engine-context (Layer E) claim. (Layer E is the
	// engine asserting facts about something else, e.g. peerAttribution.)
	engineMetadata?: #EngineMetadata @go(EngineMetadata,optional=nillable)
}

// ---------------------------------------------------------------------------
// SBOM statement: the image SBOM as a signed statement of its own.
// predicateType https://cyclonedx.org/bom
// None of the layer statements (ADR-037): its referrer carries cosign's
// predicate-type annotation and no dev.strike.statement annotation
// (ADR-059 D2).
// ---------------------------------------------------------------------------

// #SBOMStatement names the pushed image as its subject, like the provenance
// statements, and carries the top-level document of the image as its
// predicate. The producer hands the canonical document bytes to the statement
// unchanged, as raw JSON, so the predicate hashes to the digest the sealed
// statement names for "<artifact>/sbom/top-level" (#ByproductName).
#SBOMStatement: {
	"_type": "https://in-toto.io/Statement/v1" @go(Type)
	subject: [#Subject, ...#Subject]
	predicateType: "https://cyclonedx.org/bom"
	predicate:     #CycloneDXDocument @go(Predicate,type="encoding/json".RawMessage)
}

// #CycloneDXDocument pins what strike fixes of a CycloneDX document: the
// format, the specification version, the document version and the form of the
// serial number (ADR-059 D2 and D7). Everything else is left to the standard,
// whose library produces it.
#CycloneDXDocument: {
	bomFormat:    "CycloneDX"
	specVersion:  "1.7"
	version:      1
	serialNumber: =~"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	...
} @go(-)
