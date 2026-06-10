package registry

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// SigstoreBundleMediaType is the artifact type under which keylessly signed
// statement bundles are attached as OCI referrers (ADR-040 D3). It is the
// type cosign-compatible clients use to discover attestation referrers.
const SigstoreBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// statementAnnotation names which projected statement a referrer carries:
// sealed, engine-context, or informational. Discovery convenience only; the
// authoritative type is the predicateType inside the signed statement.
const statementAnnotation = "dev.strike.statement"

// StatementBundle pairs one projected statement name with its sigstore
// bundle bytes for referrer attachment.
type StatementBundle struct {
	Statement string // sealed | engine-context | informational
	Bundle    []byte
}

// ArtifactImage creates a single-layer OCI artifact image with subject
// descriptor for OCI 1.1 referrer relationship.
func ArtifactImage(content []byte, artifactType string, subject v1.Descriptor) (v1.Image, error) {
	layer := static.NewLayer(content, types.MediaType(artifactType))

	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	annotated, ok := mutate.Annotations(img, map[string]string{
		"org.opencontainers.image.created": "1970-01-01T00:00:00Z",
	}).(v1.Image)
	if !ok {
		return nil, fmt.Errorf("unexpected type from mutate.Annotations")
	}
	img = annotated

	var err error
	img, err = mutate.AppendLayers(img, layer)
	if err != nil {
		return nil, err
	}

	withSubject, ok := mutate.Subject(img, subject).(v1.Image)
	if !ok {
		return nil, fmt.Errorf("unexpected type from mutate.Subject")
	}
	img = withSubject
	return img, nil
}

// AttachStatementBundles pushes each bundle as an OCI 1.1 referrer of the
// subject manifest within the repository of target, in the caller's order.
// go-containerregistry talks to the registry's referrers API and falls back
// to the OCI referrers tag scheme on registries without it; no fallback
// logic lives here. The config media type carries the artifact type so
// registries and clients derive it per the OCI 1.1 rule (manifest
// artifactType, else config media type).
func AttachStatementBundles(ctx context.Context, target string, subject v1.Descriptor, bundles []StatementBundle) error {
	targetRef, err := name.ParseReference(target)
	if err != nil {
		return fmt.Errorf("parse target %q: %w", target, err)
	}
	repo := targetRef.Context()
	for _, b := range bundles {
		img, err := ArtifactImage(b.Bundle, SigstoreBundleMediaType, subject)
		if err != nil {
			return fmt.Errorf("referrer %s: %w", b.Statement, err)
		}
		img = mutate.ConfigMediaType(img, types.MediaType(SigstoreBundleMediaType))
		annotated, ok := mutate.Annotations(img, map[string]string{
			statementAnnotation: b.Statement,
		}).(v1.Image)
		if !ok {
			return fmt.Errorf("referrer %s: unexpected type from mutate.Annotations", b.Statement)
		}
		// Subject must be the outermost wrapper: compute() always overwrites
		// manifest.Subject with i.subject, so any wrapper added after Subject
		// would erase it. ConfigMediaType and Annotations are applied first.
		withSubject, ok := mutate.Subject(annotated, subject).(v1.Image)
		if !ok {
			return fmt.Errorf("referrer %s: unexpected type from mutate.Subject", b.Statement)
		}
		digest, err := withSubject.Digest()
		if err != nil {
			return fmt.Errorf("referrer %s: digest: %w", b.Statement, err)
		}
		if err := remote.Write(repo.Digest(digest.String()), withSubject,
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
			remote.WithContext(ctx)); err != nil {
			return fmt.Errorf("referrer %s: push: %w", b.Statement, err)
		}
	}
	return nil
}
