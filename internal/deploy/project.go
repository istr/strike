package deploy

import (
	"fmt"
	"sort"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/registry"
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

// ProjectStatements projects the internal collect-model Attestation into the
// three output in-toto statements of the trust layers (ADR-040 D3; the
// collect-model is not mutated). The layer boundary is physical:
//
//   - sealed -> SLSA Provenance v1: lane identity, declared OIDC
//     identity, declared and observed peers, observed resolver, and the
//     CP-observed engine connection, in SLSA's typed externalParameters;
//     the byproducts of the sealing act (ADR-059 D1) and the version of
//     strike (ADR-060 D5) in runDetails.
//     Sound without engine trust. No wall-clock (reproducible).
//   - engine-dependent -> engine-context: the engine-asserted peer
//     attribution (peerAttribution). Sound only under trust(E). The engine's
//     self-report (engineMetadata) is NOT here -- it carries no trust claim and
//     projects to the informational statement below.
//   - informational -> informational: deploy wall-clock, pre/post-state digests,
//     container-asserted provenance, and the engine self-report (engineMetadata).
//     Never gates.
//
// oidc is the lane-declared signing identity (ADR-040 D5); only issuer and
// identity are carried (the strike verify cross-check targets). resolvedDeps
// are the verified base-SBOM statements, the resolved dependencies of the
// sealed statement. image names the image arm of the artifacts map, whose
// SBOM document is the top-level document of the pushed image; it is read
// only where the deploy pushed.
func ProjectStatements(att *Attestation, oidc lane.OIDCConfig, resolvedDeps []ResourceDescriptor, image primitive.Identifier) (
	SLSAProvenanceStatement, EngineContextStatement, InformationalStatement, error,
) {
	subject, err := projectSubject(att.Sealed.Artifacts, att.Sealed.Pushed)
	if err != nil {
		return SLSAProvenanceStatement{}, EngineContextStatement{}, InformationalStatement{}, err
	}
	var byproducts []ResourceDescriptor
	if att.Sealed.Pushed != nil {
		byproducts, err = projectByproducts(att.Sealed.Artifacts, image)
		if err != nil {
			return SLSAProvenanceStatement{}, EngineContextStatement{}, InformationalStatement{}, err
		}
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
					OIDC:          ProvenanceOIDC{Issuer: oidc.Issuer, Identity: oidc.Identity},
					Peers:         att.Sealed.Peers,
					ObservedPeers: att.Sealed.ObservedPeers,
					Resolver:      att.Sealed.Resolver,
					Engine:        att.Sealed.Engine,
					Pushed:        att.Sealed.Pushed,
				},
				ResolvedDependencies: resolvedDeps,
			},
			RunDetails: SLSARunDetails{
				Builder:    SLSABuilder{ID: strikeBuilderID, Version: SLSABuilderVersion{Strike: strikeVersion}},
				Byproducts: byproducts,
			},
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

// StatementPayloads projects att into the statements a deploy signs and
// returns their payloads in signing order, each in the canonical form of the
// signing path: the sealed, the engine-context and the informational
// statement and, when doc is not nil, the SBOM statement over doc (ADR-059
// D2). doc is the canonical document of the image arm. The SBOM statement
// names the subject of the three and carries doc unchanged as its predicate,
// so the predicate hashes to the digest the sealed statement names for
// "<image>/sbom/top-level" (ADR-059 D1). The other arguments are those of
// ProjectStatements.
func StatementPayloads(att *Attestation, oidc lane.OIDCConfig, resolvedDeps []ResourceDescriptor, image primitive.Identifier, doc []byte) ([][]byte, error) {
	slsa, engineCtx, info, err := ProjectStatements(att, oidc, resolvedDeps, image)
	if err != nil {
		return nil, fmt.Errorf("project statements: %w", err)
	}
	statements := []any{slsa, engineCtx, info}
	if doc != nil {
		statements = append(statements, SBOMStatement{
			Type:          inTotoStatementType,
			Subject:       slsa.Subject,
			PredicateType: registry.PredicateTypeCycloneDX,
			Predicate:     doc,
		})
	}
	payloads := make([][]byte, 0, len(statements))
	for _, stmt := range statements {
		payload, mErr := canonicalJSON(stmt)
		if mErr != nil {
			return nil, fmt.Errorf("marshal statement: %w", mErr)
		}
		payloads = append(payloads, payload)
	}
	return payloads, nil
}

// projectSubject builds the in-toto subject list. Where the deploy pushed, the
// subject is the artifact as the registry serves it -- one subject, named by
// the repository and carrying the pushed manifest digest -- so a verifier
// dereferences the published artifact and hash-checks it (ADR-051 D4). The
// produced identities are not the subject there: the engine re-encodes on
// export, so a produced manifest digest names bytes no registry serves
// (ADR-046); they project as byproducts instead (ADR-059 D1). Without a push
// the artifacts are the subject. The list is sorted by name: the sealed
// statement must be reproducible (byte-identical inputs -> byte-identical
// output), and Go map iteration order is not stable.
func projectSubject(artifacts map[primitive.Identifier]record.Artifact, pushed *PushedArtifact) ([]Subject, error) {
	if pushed != nil {
		d, err := primitive.ParseDigest(pushed.Digest)
		if err != nil {
			return nil, fmt.Errorf("pushed subject: %w", err)
		}
		return []Subject{{Name: string(pushed.Repository), Digest: &DigestSet{SHA256: d.Hex()}}}, nil
	}
	subjects := make([]Subject, 0, len(artifacts))
	for name, art := range artifacts {
		d, err := primitive.ParseDigest(art.Digest)
		if err != nil {
			return nil, fmt.Errorf("subject %q: %w", name, err)
		}
		subjects = append(subjects, Subject{Name: string(name), Digest: &DigestSet{SHA256: d.Hex()}})
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].Name < subjects[j].Name })
	return subjects, nil
}

// projectByproducts renders what the sealing act generated beside its subject
// as in-toto byproducts (ADR-059 D1). Every artifact contributes its produced
// identity under its artifacts name: the content identity the control plane
// produced and checked the engine export against, distinct from the pushed
// subject the registry serves. An artifact the deploy cataloged contributes
// its SBOM document as well, with the media type of the document and the
// sha256 of its bytes: under "<name>/sbom" for a region, and under
// "<name>/sbom/top-level" for image, the image arm, whose document the SBOM
// statement carries. Sorted by name, for the same reproducibility reason as
// projectSubject.
func projectByproducts(artifacts map[primitive.Identifier]record.Artifact, image primitive.Identifier) ([]ResourceDescriptor, error) {
	byproducts := make([]ResourceDescriptor, 0, 2*len(artifacts))
	for name, art := range artifacts {
		produced, err := primitive.ParseDigest(art.Digest)
		if err != nil {
			return nil, fmt.Errorf("byproduct %q: %w", name, err)
		}
		byproducts = append(byproducts, ResourceDescriptor{Name: string(name), Digest: &DigestSet{SHA256: produced.Hex()}})
		if art.SBOM == nil {
			continue
		}
		document, err := primitive.ParseDigest(art.SBOM.CycloneDX)
		if err != nil {
			return nil, fmt.Errorf("byproduct %q: sbom: %w", name, err)
		}
		level := "/sbom"
		if name == image {
			level = "/sbom/top-level"
		}
		byproducts = append(byproducts, ResourceDescriptor{
			Name:      string(name) + level,
			Digest:    &DigestSet{SHA256: document.Hex()},
			MediaType: sbomMediaType,
		})
	}
	sort.Slice(byproducts, func(i, j int) bool { return byproducts[i].Name < byproducts[j].Name })
	return byproducts, nil
}
