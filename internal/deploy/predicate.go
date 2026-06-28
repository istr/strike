package deploy

import (
	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/provenance"
	"github.com/istr/strike/internal/target"
)

// Output attestation predicate types (ADR-040 D3). These are the standard-
// ecosystem shapes strike signs and publishes. The projection from the
// internal Attestation collect-model into these shapes is a later instruction;
// this file is the type definitions only. Mirrors contract/attest/predicate.cue and is
// validated against it (predicate_test.go).

// DigestSet is an in-toto DigestSet, typed to the algorithms strike emits.
type DigestSet struct {
	SHA256    primitive.Sha256    `json:"sha256,omitempty"`
	SHA512    string              `json:"sha512,omitempty"`
	GitCommit primitive.GitCommit `json:"gitCommit,omitempty"`
}

// ResourceDescriptor is the in-toto ResourceDescriptor (fields strike emits).
type ResourceDescriptor struct {
	Digest           *DigestSet `json:"digest,omitempty"`
	Name             string     `json:"name,omitempty"`
	URI              string     `json:"uri,omitempty"`
	MediaType        string     `json:"mediaType,omitempty"`
	DownloadLocation string     `json:"downloadLocation,omitempty"`
}

// Subject is one in-toto statement subject: a deployed artifact.
type Subject struct {
	Digest DigestSet `json:"digest"`
	Name   string    `json:"name"`
}

// SLSAProvenanceStatement is the sealed (Layer V) output: an in-toto Statement
// v1 wrapping a SLSA Provenance v1 predicate.
type SLSAProvenanceStatement struct {
	Predicate     SLSAProvenancePredicate `json:"predicate"`
	Type          string                  `json:"_type"`
	PredicateType string                  `json:"predicateType"`
	Subject       []Subject               `json:"subject"`
}

// SLSAProvenancePredicate is the SLSA Provenance v1 predicate.
type SLSAProvenancePredicate struct {
	RunDetails      SLSARunDetails      `json:"runDetails"`
	BuildDefinition SLSABuildDefinition `json:"buildDefinition"`
}

// SLSABuildDefinition is the SLSA BuildDefinition.
type SLSABuildDefinition struct {
	ExternalParameters   StrikeExternalParameters `json:"externalParameters"`
	BuildType            string                   `json:"buildType"`
	ResolvedDependencies []ResourceDescriptor     `json:"resolvedDependencies,omitempty"`
}

// StrikeExternalParameters occupies SLSA's open externalParameters slot with
// strike's typed Layer-V facts (Fork C, Fork D). EngineConnection is Layer V
// and lives here, not in the engine-context predicate.
type StrikeExternalParameters struct {
	Target        target.Deploy           `json:"target"`
	Peers         map[string][]lane.Peer  `json:"peers"`
	ObservedPeers map[string]ObservedPeer `json:"observedPeers,omitempty"`
	Resolver      ResolverRecord          `json:"resolver"`
	Engine        endpoint.Engine         `json:"engine,omitempty"`
	OIDC          ProvenanceOIDC          `json:"oidc"`
	LaneID        string                  `json:"laneId"`
	LaneDigest    primitive.Digest        `json:"laneDigest"`
}

// ProvenanceOIDC is the declared signing identity carried into the sealed
// provenance (ADR-040 D5); the strike verify cross-check targets.
type ProvenanceOIDC struct {
	Issuer   string `json:"issuer"`
	Identity string `json:"identity"`
}

// SLSARunDetails is the SLSA RunDetails.
type SLSARunDetails struct {
	Metadata   *SLSABuildMetadata   `json:"metadata,omitempty"`
	Builder    SLSABuilder          `json:"builder"`
	Byproducts []ResourceDescriptor `json:"byproducts,omitempty"`
}

// SLSABuilder is the SLSA Builder identity.
type SLSABuilder struct {
	ID string `json:"id"`
}

// SLSABuildMetadata carries only reproducible fields (no wall-clock).
type SLSABuildMetadata struct {
	InvocationID string `json:"invocationId,omitempty"`
}

// EngineContextStatement is the engine_dependent (Layer E) output: an in-toto
// Statement v1 wrapping a strike-defined engine-context predicate.
type EngineContextStatement struct {
	Predicate     EngineContextPredicate `json:"predicate"`
	Type          string                 `json:"_type"`
	PredicateType string                 `json:"predicateType"`
	Subject       []Subject              `json:"subject"`
}

// EngineContextPredicate carries the Layer-E claim only: engine-asserted step
// attribution. EngineConnection (Layer V) and the engine self-report
// (engineMetadata, informational) are not here.
type EngineContextPredicate struct {
	PeerAttribution map[string][]string `json:"peerAttribution,omitempty"`
}

// InformationalStatement is the informational output: an in-toto Statement v1
// wrapping a strike-defined informational predicate. Signed but never gating a
// verification exit (ADR-040 D3); a verifier discriminates it by predicateType
// and never lets its contents affect the exit (ADR-037).
type InformationalStatement struct {
	Predicate     InformationalPredicate `json:"predicate"`
	Type          string                 `json:"_type"`
	PredicateType string                 `json:"predicateType"`
	Subject       []Subject              `json:"subject"`
}

// InformationalPredicate carries the informational-layer fields (ADR-037): the
// deploy wall-clock (informational, not canonical -- Rekor integratedTime is
// canonical), the CP-canonical pre/post-state digests (container-produced
// bytes, CP-hashed; the hash transports them, it does not lift them out of the
// container-asserted class), and the container-asserted, engine-relayed
// provenance records. None of these gate. This is the one output statement
// that carries a wall-clock; the sealed provenance is reproducible and omits
// it.
type InformationalPredicate struct {
	Timestamp       clock.Time          `json:"timestamp,omitempty"`
	EngineMetadata  *EngineMetadata     `json:"engineMetadata,omitempty"`
	PreStateDigest  primitive.Digest    `json:"preStateDigest"`
	PostStateDigest primitive.Digest    `json:"postStateDigest"`
	Provenance      []provenance.Record `json:"provenance"`
}
