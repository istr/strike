package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
)

// SigstoreBundleMediaType is the artifact type under which keylessly signed
// statement bundles are attached as OCI referrers (ADR-040 D3). It is the
// type cosign-compatible clients use to discover attestation referrers.
const SigstoreBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// statementAnnotation names the trust layer of the statement a referrer
// carries: sealed, engine-dependent, or informational. Discovery convenience
// only; the authoritative type is the predicateType inside the signed statement.
const statementAnnotation = "dev.strike.statement"

// maxBundleBytes bounds a single fetched referrer bundle. A real sigstore
// statement bundle is a few KiB; this is generous headroom that still refuses
// an unbounded allocation from a hostile or buggy registry, mirroring the 1 MiB
// cap on the keyless HTTP clients.
const maxBundleBytes = 8 << 20 // 8 MiB

// StatementBundle pairs one projected statement's trust layer with its
// sigstore bundle bytes for referrer attachment.
type StatementBundle struct {
	Statement record.TrustLayer
	Bundle    []byte
}

// ArtifactImage builds a push-ready OCI 1.1 referrer of subject in the
// artifact form the image specification gives for content without a
// configuration, the form cosign uses: the manifest artifactType names
// artifactType, the config is the OCI empty descriptor, and a single layer
// carries content under the same media type. The manifest is assembled here
// because go-containerregistry's mutate package cannot set an image
// manifest's artifactType. The caller's annotations are merged over the
// reproducible created timestamp and win on collision.
func ArtifactImage(content []byte, artifactType string, subject v1.Descriptor, annotations map[string]string) (v1.Image, error) {
	config := []byte("{}")
	configSum := sha256.Sum256(config)
	layerSum := sha256.Sum256(content)
	layerDigest := v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(layerSum[:])}

	ann := map[string]string{"org.opencontainers.image.created": "1970-01-01T00:00:00Z"}
	maps.Copy(ann, annotations)
	manifest := v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config: v1.Descriptor{
			MediaType: types.OCIEmptyJSON,
			Size:      int64(len(config)),
			Digest:    v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(configSum[:])},
		},
		Layers: []v1.Descriptor{{
			MediaType: types.MediaType(artifactType),
			Size:      int64(len(content)),
			Digest:    layerDigest,
		}},
		Annotations:  ann,
		Subject:      &subject,
		ArtifactType: artifactType,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("artifact manifest: %w", err)
	}
	return partial.CompressedToImage(&memImage{
		manifest: manifest,
		raw:      raw,
		config:   config,
		blobs:    map[string][]byte{"blobs/sha256/" + layerDigest.Hex: content},
	})
}

// AttachStatementBundles pushes each bundle as an OCI 1.1 referrer of the
// subject manifest within the repository of target, in the caller's order,
// and returns the descriptor of every referrer it pushed, in the same order,
// for the read-after-write that follows (ADR-051 amendment 2026-11-08). The
// registry must serve the referrers API: the referrers tag fallback is
// refused, so a registry without the API fails the push instead of receiving
// a tag (ADR-058). ArtifactImage owns the referrer wrapping, including how
// the artifact type is carried. The caller's remote options -- the
// trust-anchored transport that carries the declared credential -- apply to
// every write; no ambient credential is consulted (ADR-058 D6).
func AttachStatementBundles(ctx context.Context, target string, subject v1.Descriptor, bundles []StatementBundle, opts ...remote.Option) ([]v1.Descriptor, error) {
	targetRef, err := name.ParseReference(target)
	if err != nil {
		return nil, fmt.Errorf("parse target %q: %w", target, err)
	}
	repo := targetRef.Context()
	writeOpts := append([]remote.Option{
		remote.WithReferrersTagFallback(false),
		remote.WithContext(ctx),
	}, opts...)
	attached := make([]v1.Descriptor, 0, len(bundles))
	for _, b := range bundles {
		img, err := ArtifactImage(b.Bundle, SigstoreBundleMediaType, subject, map[string]string{
			statementAnnotation: string(b.Statement),
		})
		if err != nil {
			return nil, fmt.Errorf("referrer %s: %w", b.Statement, err)
		}
		desc, err := partial.Descriptor(img)
		if err != nil {
			return nil, fmt.Errorf("referrer %s: digest: %w", b.Statement, err)
		}
		if err := remote.Write(repo.Digest(desc.Digest.String()), img, writeOpts...); err != nil {
			return nil, fmt.Errorf("referrer %s of %s: push: %w", b.Statement, subject.Digest, err)
		}
		attached = append(attached, *desc)
	}
	return attached, nil
}

// FetchStatementBundles is the consumer counterpart to AttachStatementBundles:
// given a digest-pinned subject image, it discovers the sigstore statement
// bundles attached as OCI 1.1 referrers, fetches each bundle's bytes, and
// returns them paired with the trust layer from the referrer's
// dev.strike.statement annotation, in registry-listed order. A referrer whose
// annotation names no trust layer is skipped and reported.
//
// This is a sealed-layer read: the bytes come from the registry at the subject's
// own digest, independently of any engine, so a downstream verifier checks the
// actual published payload rather than a relayed copy. The subject must be
// digest-pinned -- name.NewDigest rejects a tag -- because a mutable reference
// cannot anchor a reproducible verification.
//
// Discovery is by artifact-type filter (the cosign-compatible referrers query);
// identification and projection are read back from each fetched manifest (its
// artifactType and annotation), which is authoritative, rather than from the
// index descriptor. It is strike verify's read, which declares no registry, so
// it reads through go-containerregistry's default transport.
func FetchStatementBundles(ctx context.Context, subjectRef string) ([]StatementBundle, error) {
	ref, err := name.NewDigest(subjectRef)
	if err != nil {
		return nil, fmt.Errorf("subject must be digest-pinned: %w", err)
	}
	return fetchReferrers(ctx, ref, remote.DefaultTransport, fetchOneBundle)
}

// fetchReferrers discovers the sigstore-bundle referrers of a digest-pinned
// subject -- the same artifactType filter both producers (strike's own and
// cosign) are indexed under -- maps each referrer manifest through fetch, and
// drops the nil results fetch returns for referrers it skips. It is shared by
// FetchStatementBundles (strike's own bundles) and FetchBaseSBOMReferrers
// (cosign base SBOMs), which differ only in the per-referrer reader. The
// registry must serve the referrers API: the referrers tag fallback is
// refused, so a registry without the API fails the read (ADR-058). Every
// read is anonymous, over the transport rt the caller hands in; no ambient
// credential is consulted (ADR-058 D6).
func fetchReferrers[T any](ctx context.Context, ref name.Digest, rt http.RoundTripper, fetch func(context.Context, name.Digest, http.RoundTripper) (*T, error)) ([]T, error) {
	repo := ref.Context()
	idx, err := remote.Referrers(ref,
		remote.WithFilter("artifactType", SigstoreBundleMediaType),
		remote.WithReferrersTagFallback(false),
		remote.WithContext(ctx),
		remote.WithTransport(rt))
	if err != nil {
		return nil, fmt.Errorf("list referrers of %s: %w", ref, err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("referrers index: %w", err)
	}
	var out []T
	for _, d := range im.Manifests {
		v, err := fetch(ctx, repo.Digest(d.Digest.String()), rt)
		if err != nil {
			return nil, fmt.Errorf("referrer %s: %w", d.Digest, err)
		}
		if v != nil {
			out = append(out, *v)
		}
	}
	return out, nil
}

// fetchOneBundle fetches a single referrer manifest and its bundle layer. It
// returns nil (no error) when the referrer is not a strike statement bundle,
// so the caller skips it rather than failing the whole read. A referrer that
// selects as a strike statement bundle but is malformed -- wrong layer count
// or a non-bundle layer media type -- is an error, not a skip.
func fetchOneBundle(ctx context.Context, ref name.Digest, rt http.RoundTripper) (*StatementBundle, error) {
	img, err := remote.Image(ref, remote.WithContext(ctx), remote.WithTransport(rt))
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	man, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	// Authoritative re-check: the manifest names its own artifact type. Skip
	// anything that is not a sigstore bundle.
	if man.ArtifactType != SigstoreBundleMediaType {
		return nil, nil
	}
	// The annotation names the statement's trust layer. A value outside the
	// vocabulary is not a statement this reader knows: it is skipped before its
	// bundle layer is read, so no foreign bundle bytes are fetched.
	layer := record.TrustLayer(man.Annotations[statementAnnotation])
	switch layer {
	case record.TrustLayerSealed, record.TrustLayerEngineDependent, record.TrustLayerInformational:
	default:
		log.Print("INFO  ignored a statement bundle with an unknown layer annotation")
		return nil, nil
	}
	bundle, err := readBundleLayer(img)
	if err != nil {
		return nil, err
	}
	return &StatementBundle{
		Statement: layer,
		Bundle:    bundle,
	}, nil
}

// readBundleLayer reads the bundle a referrer carries: exactly one layer, of
// the sigstore bundle media type, read up to maxBundleBytes so a hostile or
// buggy registry cannot force an unbounded allocation. Both referrer readers
// share it; which referrers they select stays with each reader.
func readBundleLayer(img v1.Image) ([]byte, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("layers: %w", err)
	}
	if len(layers) != 1 {
		return nil, fmt.Errorf("expected 1 layer, got %d", len(layers))
	}
	mt, err := layers[0].MediaType()
	if err != nil {
		return nil, fmt.Errorf("layer media type: %w", err)
	}
	if string(mt) != SigstoreBundleMediaType {
		return nil, fmt.Errorf("layer media type %q is not %s", mt, SigstoreBundleMediaType)
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
	return bundle, nil
}

// FetchTrustRoot pulls a sigstore trusted_root.json published as a single-layer
// OCI image at a digest-pinned reference, returning the raw JSON bytes for
// verify.ParseTrustedRoot. The reference must be digest-pinned -- name.NewDigest
// rejects a tag -- because the digest is the trust anchor: the operator pins the
// exact bytes they trust. The image is a plain artifact, not a referrer of
// anything; its sole layer is the document. The read is bounded by maxBundleBytes
// against a hostile or buggy registry. src hands out the transport the read
// goes through.
func FetchTrustRoot(ctx context.Context, ref primitive.ImageRef, src Transports) ([]byte, error) {
	s := string(ref)
	d, err := name.NewDigest(s)
	if err != nil {
		return nil, fmt.Errorf("trust root ref must be digest-pinned: %w", err)
	}
	rt, err := src.Transport(ref)
	if err != nil {
		return nil, err
	}
	img, err := remote.Image(d, remote.WithContext(ctx), remote.WithTransport(rt))
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

// Base-SBOM predicate types strike recognizes as scope selectors when reading a
// base image's signed SBOM attestations (cosign attest --type cyclonedx |
// spdxjson). They select which referrers are treated as the base's SBOM
// attestations; they are read from an unsigned manifest annotation and are
// therefore scope only, never trust. Trust is the signer identity and subject
// binding the verifying caller checks over the returned bundle.
const (
	PredicateTypeCycloneDX = "https://cyclonedx.org/bom"
	PredicateTypeSPDX      = "https://spdx.dev/Document"
)

// bundlePredicateTypeAnnotation is the OCI manifest annotation under which
// cosign records the in-toto predicate type of an attestation referrer.
const bundlePredicateTypeAnnotation = "dev.sigstore.bundle.predicateType"

// BaseSBOMReferrer is one cosign-produced, SBOM-typed sigstore bundle attached
// as an OCI referrer of a base image. Digest is the referrer manifest digest --
// the stable, content-addressed handle a downstream verifier dereferences to
// re-verify the base SBOM offline, without contacting strike or the engine.
// PredicateType is the unsigned annotation hint used for scope selection; the
// authoritative predicate type lives inside the signed statement and is read by
// the verifying caller. Bundle is the raw sigstore v0.3 bundle (DSSE envelope
// plus verification material), handed to the verifying caller unchanged.
type BaseSBOMReferrer struct {
	Digest        string // referrer manifest digest, "sha256:..."
	PredicateType string // scope-selector hint, not trust-bearing
	Bundle        []byte
}

// FetchBaseSBOMReferrers lists the SBOM attestations attached to a digest-pinned
// base image as OCI referrers and returns each as raw bundle bytes plus its
// referrer-manifest digest. Discovery uses the same artifactType filter as
// strike's own bundles. Unlike fetchOneBundle (strike's own producer), this
// does NOT re-check the manifest artifactType -- a foreign publisher's
// referrer is taken in whatever form the registry indexed under the filter --
// and it selects by cosign's predicate-type annotation rather than a
// strike-private one. The bundle is read from the single layer, whose media
// type both producers set to the bundle type. Only the SBOM predicate types
// are returned; other attestation referrers (for example a SLSA provenance
// attestation) are skipped. Verification -- signer identity and subject
// binding -- is the caller's responsibility; this is fetch only.
//
// The subject must be digest-pinned (name.NewDigest rejects a tag) because a
// mutable reference cannot anchor a reproducible verification. src hands out
// the transport the read goes through.
func FetchBaseSBOMReferrers(ctx context.Context, baseRef primitive.ImageRef, src Transports) ([]BaseSBOMReferrer, error) {
	s := string(baseRef)
	ref, err := name.NewDigest(s)
	if err != nil {
		return nil, fmt.Errorf("base image must be digest-pinned: %w", err)
	}
	rt, err := src.Transport(baseRef)
	if err != nil {
		return nil, err
	}
	return fetchReferrers(ctx, ref, rt, fetchOneBaseSBOM)
}

// fetchOneBaseSBOM fetches a single referrer and returns it when it is an
// SBOM-typed sigstore bundle, or nil (no error) when it is some other
// attestation to be skipped. A referrer that selects as an SBOM but is
// malformed -- wrong layer count or a non-bundle layer media type -- is an
// error, not a skip, so a broken base SBOM surfaces rather than vanishing.
func fetchOneBaseSBOM(ctx context.Context, ref name.Digest, rt http.RoundTripper) (*BaseSBOMReferrer, error) {
	img, err := remote.Image(ref, remote.WithContext(ctx), remote.WithTransport(rt))
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	man, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	pt := man.Annotations[bundlePredicateTypeAnnotation]
	if pt != PredicateTypeCycloneDX && pt != PredicateTypeSPDX {
		return nil, nil // not an SBOM attestation; skip
	}
	bundle, err := readBundleLayer(img)
	if err != nil {
		return nil, err
	}
	return &BaseSBOMReferrer{
		Digest:        ref.DigestStr(),
		PredicateType: pt,
		Bundle:        bundle,
	}, nil
}
