package registry

import (
	"context"
	"fmt"
	"io"

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

// maxBundleBytes bounds a single fetched referrer bundle. A real sigstore
// statement bundle is a few KiB; this is generous headroom that still refuses
// an unbounded allocation from a hostile or buggy registry, mirroring the 1 MiB
// cap on the keyless HTTP clients.
const maxBundleBytes = 8 << 20 // 8 MiB

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

// FetchStatementBundles is the consumer counterpart to AttachStatementBundles:
// given a digest-pinned subject image, it discovers the sigstore statement
// bundles attached as OCI 1.1 referrers, fetches each bundle's bytes, and
// returns them paired with the projection name from the referrer's
// dev.strike.statement annotation, in registry-listed order.
//
// This is a Layer-V read: the bytes come from the registry at the subject's
// own digest, independently of any engine, so a downstream verifier checks the
// actual published payload rather than a relayed copy. The subject must be
// digest-pinned -- name.NewDigest rejects a tag -- because a mutable reference
// cannot anchor a reproducible verification.
//
// Discovery is by artifact-type filter (the cosign-compatible referrers query);
// identification and projection are read back from each fetched manifest (its
// config media type and annotation), which is authoritative, rather than from
// the index descriptor.
func FetchStatementBundles(ctx context.Context, subjectRef string) ([]StatementBundle, error) {
	ref, err := name.NewDigest(subjectRef)
	if err != nil {
		return nil, fmt.Errorf("subject must be digest-pinned: %w", err)
	}
	repo := ref.Context()
	idx, err := remote.Referrers(ref,
		remote.WithFilter("artifactType", SigstoreBundleMediaType),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("list referrers of %s: %w", subjectRef, err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("referrers index: %w", err)
	}
	var out []StatementBundle
	for _, d := range im.Manifests {
		sb, err := fetchOneBundle(ctx, repo.Digest(d.Digest.String()))
		if err != nil {
			return nil, fmt.Errorf("referrer %s: %w", d.Digest, err)
		}
		if sb != nil {
			out = append(out, *sb)
		}
	}
	return out, nil
}

// fetchOneBundle fetches a single referrer manifest and its bundle layer. It
// returns nil (no error) when the referrer is not a strike statement bundle,
// so the caller skips it rather than failing the whole read.
func fetchOneBundle(ctx context.Context, ref name.Digest) (*StatementBundle, error) {
	img, err := remote.Image(ref,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	man, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	// Authoritative re-check: the artifact type the producer set lives in the
	// config media type. Skip anything that is not a strike bundle.
	if string(man.Config.MediaType) != SigstoreBundleMediaType {
		return nil, nil
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("layers: %w", err)
	}
	if len(layers) != 1 {
		return nil, fmt.Errorf("expected 1 layer, got %d", len(layers))
	}
	rc, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("open layer: %w", err)
	}
	bundle, readErr := io.ReadAll(io.LimitReader(rc, maxBundleBytes+1))
	closeErr := rc.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read bundle: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close layer: %w", closeErr)
	}
	if len(bundle) > maxBundleBytes {
		return nil, fmt.Errorf("bundle exceeds %d bytes", maxBundleBytes)
	}
	return &StatementBundle{
		Statement: man.Annotations[statementAnnotation],
		Bundle:    bundle,
	}, nil
}

// FetchTrustRoot pulls a sigstore trusted_root.json published as a single-layer
// OCI image at a digest-pinned reference, returning the raw JSON bytes for
// verify.ParseTrustedRoot. The reference must be digest-pinned -- name.NewDigest
// rejects a tag -- because the digest is the trust anchor: the operator pins the
// exact bytes they trust. The image is a plain artifact, not a referrer of
// anything; its sole layer is the document. The read is bounded by maxBundleBytes
// against a hostile or buggy registry.
func FetchTrustRoot(ctx context.Context, ref string) ([]byte, error) {
	d, err := name.NewDigest(ref)
	if err != nil {
		return nil, fmt.Errorf("trust root ref must be digest-pinned: %w", err)
	}
	img, err := remote.Image(d,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("fetch trust root %s: %w", ref, err)
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("trust root %s: layers: %w", ref, err)
	}
	if len(layers) != 1 {
		return nil, fmt.Errorf("trust root %s: expected 1 layer, got %d", ref, len(layers))
	}
	rc, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("trust root %s: open layer: %w", ref, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(rc, maxBundleBytes+1))
	closeErr := rc.Close()
	if readErr != nil {
		return nil, fmt.Errorf("trust root %s: read: %w", ref, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("trust root %s: close layer: %w", ref, closeErr)
	}
	if len(data) > maxBundleBytes {
		return nil, fmt.Errorf("trust root %s: exceeds %d bytes", ref, maxBundleBytes)
	}
	return data, nil
}
