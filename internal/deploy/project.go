package deploy

import (
	"fmt"
	"sort"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
)

// Output-statement constants (ADR-040 D3). The projected statements are
// standard in-toto Statement v1 documents; the DSSE payload type is in-toto
// (sign.go), not the strike-specific type (ADR-013).
const (
	inTotoStatementType = "https://in-toto.io/Statement/v1"
	slsaProvenanceType  = "https://slsa.dev/provenance/v1"
	engineContextType   = "https://istr.dev/strike/predicates/engine-context/v1"
	informationalType   = "https://istr.dev/strike/predicates/informational/v1"
	laneBuildType       = "https://istr.dev/strike/buildtypes/lane/v1"
	strikeBuilderID     = "https://istr.dev/strike"
)

// projectStatements projects the internal collect-model Attestation into the
// three output in-toto statements (ADR-040 D3, Fork A; the collect-model is not
// mutated). The layer boundary is physical:
//
//   - sealed (Layer V) -> SLSA Provenance v1: lane identity, declared OIDC
//     identity, declared and observed peers, observed resolver, and the
//     CP-observed engine connection, in SLSA's typed externalParameters (Fork
//     D). Sound without engine trust. No wall-clock (reproducible).
//   - engine_dependent (Layer E) -> engine-context: the engine-asserted peer
//     attribution (peerAttribution). Sound only under trust(E). The engine's
//     self-report (engineMetadata) is NOT here -- it carries no trust claim and
//     projects to the informational statement below.
//   - informational -> informational: deploy wall-clock, pre/post-state digests,
//     container-asserted provenance, and the engine self-report (engineMetadata).
//     Never gates.
//
// oidc is the lane-declared signing identity (ADR-040 D5); only issuer and
// identity are carried (the strike verify cross-check targets).
func projectStatements(att *Attestation, oidc lane.OIDCConfig, resolvedDeps []ResourceDescriptor) (
	SLSAProvenanceStatement, EngineContextStatement, InformationalStatement, error,
) {
	subject, err := projectSubject(att.Sealed.Artifacts)
	if err != nil {
		return SLSAProvenanceStatement{}, EngineContextStatement{}, InformationalStatement{}, err
	}

	slsa := SLSAProvenanceStatement{
		Type:          inTotoStatementType,
		PredicateType: slsaProvenanceType,
		Subject:       subject,
		Predicate: SLSAProvenancePredicate{
			BuildDefinition: SLSABuildDefinition{
				BuildType: laneBuildType,
				ExternalParameters: StrikeExternalParameters{
					LaneID:        att.Sealed.LaneID,
					LaneDigest:    att.Sealed.LaneDigest,
					Target:        att.Sealed.Target,
					OIDC:          ProvenanceOIDC{Issuer: oidc.Issuer, Identity: oidc.Identity},
					Peers:         att.Sealed.Peers,
					ObservedPeers: att.Sealed.ObservedPeers,
					Resolver:      att.Sealed.Resolver,
					Engine:        att.Sealed.Engine,
				},
				ResolvedDependencies: resolvedDeps,
			},
			RunDetails: SLSARunDetails{Builder: SLSABuilder{ID: strikeBuilderID}},
		},
	}

	engineCtx := EngineContextStatement{
		Type:          inTotoStatementType,
		PredicateType: engineContextType,
		Subject:       subject,
		Predicate:     EngineContextPredicate{PeerAttribution: att.EngineDependent.PeerAttribution},
	}

	info := InformationalStatement{
		Type:          inTotoStatementType,
		PredicateType: informationalType,
		Subject:       subject,
	}
	if att.Informational != nil {
		info.Predicate = InformationalPredicate{
			Timestamp:       att.Informational.Timestamp,
			PreStateDigest:  att.Informational.PreStateDigest,
			PostStateDigest: att.Informational.PostStateDigest,
			Provenance:      att.Informational.Provenance,
			EngineMetadata:  att.Informational.EngineMetadata,
		}
	}

	return slsa, engineCtx, info, nil
}

// projectSubject builds the in-toto subject list from the sealed artifacts.
// Each artifact's manifest digest (a "sha256:<hex>" string) becomes a DigestSet
// subject. The list is sorted by name: the sealed statement must be
// reproducible (byte-identical inputs -> byte-identical output), and Go map
// iteration order is not stable.
func projectSubject(artifacts map[string]record.Artifact) ([]Subject, error) {
	subjects := make([]Subject, 0, len(artifacts))
	for name, art := range artifacts {
		d, err := primitive.ParseDigest(art.Digest)
		if err != nil {
			return nil, fmt.Errorf("subject %q: %w", name, err)
		}
		subjects = append(subjects, Subject{Name: name, Digest: DigestSet{SHA256: d.Hex()}})
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].Name < subjects[j].Name })
	return subjects, nil
}
