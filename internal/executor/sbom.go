package executor

import (
	"bytes"
	"debug/buildinfo"
	"fmt"
	"log"
	"strings"

	"github.com/istr/strike/internal/clock"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// SBOMSource describes where base image SBOM data was found.
type SBOMSource int

// SBOMSourceReferrer indicates the SBOM was found via OCI 1.1 referrers.
// SBOMSourceFallback indicates the cosign tag convention was used.
// SBOMSourceNone indicates no SBOM was found on the base image.
const (
	SBOMSourceReferrer SBOMSource = iota
	SBOMSourceFallback
	SBOMSourceNone
)

var sbomArtifactTypes = []string{
	"application/vnd.cyclonedx+json",
	"application/vnd.cyclonedx",
	"application/spdx+json",
	"application/vnd.syft+json",
}

// GenerateSBOM produces a CycloneDX 1.6 JSON SBOM for a packed image.
//
// binaryPath is the host path of the compiled Go binary being packaged.
// imageDigest is the sha256 digest of the assembled image manifest
// (used as the SBOM subject).
// baseRef is the fully-qualified base image reference including digest
// (e.g. "cgr.dev/chainguard/static@sha256:...").
//
// Returns the SBOM as a JSON byte slice ready to attach as an OCI artefact.
func GenerateSBOM(binaryPath, imageDigest, baseRef string, buildTime clock.Time) ([]byte, error) {
	info, err := buildinfo.ReadFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("read build info from %q: %w", binaryPath, err)
	}

	// Build component list from Go module dependencies
	components := make([]cdx.Component, 0, len(info.Deps))
	for _, dep := range info.Deps {
		h := strings.TrimPrefix(dep.Sum, "h1:")
		comp := cdx.Component{
			Type:    cdx.ComponentTypeLibrary,
			Name:    dep.Path,
			Version: dep.Version,
		}
		if h != "" {
			comp.Hashes = &[]cdx.Hash{{
				Algorithm: cdx.HashAlgoSHA256,
				Value:     h,
			}}
		}
		components = append(components, comp)
	}

	// Probe base image for existing SBOM (best-effort)
	sbomSource, description, probeErr := ProbeBaseImageSBOM(baseRef)
	if probeErr != nil {
		log.Printf("WARN   sbom: base image probe failed (%v) -- "+
			"OS-level packages will be absent from SBOM", probeErr)
	}

	var baseComponents []cdx.Component
	var fetchErr error
	switch sbomSource {
	case SBOMSourceNone:
		log.Print("WARN   sbom: base image has no attached SBOM -- " +
			"OS-level packages will be absent from this build's SBOM.\n" +
			"       Recommended base images with SBOM support:\n" +
			"         cgr.dev/chainguard/static  (Chainguard, full SBOM)\n" +
			"         gcr.io/distroless/static   (Google, partial)")
	case SBOMSourceReferrer:
		baseComponents, fetchErr = fetchBaseComponents(baseRef)
		if fetchErr != nil {
			log.Printf("WARN   sbom: base component fetch failed: %v", fetchErr)
		}
	case SBOMSourceFallback:
		log.Printf("INFO   sbom: base image SBOM found via tag convention (%s)",
			description)
		baseComponents, fetchErr = fetchBaseComponents(baseRef)
		if fetchErr != nil {
			log.Printf("WARN   sbom: base component fetch failed: %v", fetchErr)
		}
	}

	// Append base components with "base:" BOMRef prefix
	for _, bc := range baseComponents {
		bc.BOMRef = "base:" + bc.BOMRef
		components = append(components, bc)
	}

	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Timestamp: buildTime.Format(clock.RFC3339),
		Component: &cdx.Component{
			Type:    cdx.ComponentTypeContainer,
			Name:    "strike",
			Version: info.Main.Version,
			BOMRef:  imageDigest,
		},
	}
	bom.Components = &components

	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(false)
	if err := enc.Encode(bom); err != nil {
		return nil, fmt.Errorf("encode SBOM: %w", err)
	}
	return buf.Bytes(), nil
}

// ProbeBaseImageSBOM checks for an attached SBOM on the base image.
// Returns source type, a human-readable description, and any probe error.
// A probe error is non-fatal: treat it as SBOMSourceNone and warn.
func ProbeBaseImageSBOM(baseRef string) (SBOMSource, string, error) {
	ref, err := name.ParseReference(baseRef)
	if err != nil {
		return SBOMSourceNone, "", fmt.Errorf("parse ref: %w", err)
	}

	digestRef, ok := ref.(name.Digest)
	if !ok {
		return SBOMSourceNone, "", fmt.Errorf("ref %q is not a digest reference", baseRef)
	}

	// Try OCI 1.1 Referrers API
	if source, desc, found := probeReferrers(digestRef); found {
		return source, desc, nil
	}

	// Fallback: check cosign tag convention sha256-<hex>.att
	if source, desc, found := probeFallbackTag(digestRef); found {
		return source, desc, nil
	}

	return SBOMSourceNone, "", nil
}

// probeReferrers checks the OCI 1.1 Referrers API for an SBOM attachment.
func probeReferrers(digestRef name.Digest) (SBOMSource, string, bool) {
	idx, err := remote.Referrers(digestRef)
	if err != nil {
		return SBOMSourceNone, "", false
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return SBOMSourceNone, "", false
	}
	for _, desc := range manifest.Manifests {
		for _, at := range sbomArtifactTypes {
			if string(desc.ArtifactType) == at {
				return SBOMSourceReferrer, fmt.Sprintf("referrer: %s", at), true
			}
		}
	}
	return SBOMSourceNone, "", false
}

// probeFallbackTag checks the cosign sha256-<hex>.att tag convention.
func probeFallbackTag(digestRef name.Digest) (SBOMSource, string, bool) {
	digestStr := digestRef.DigestStr() // "sha256:abc..."
	if !strings.HasPrefix(digestStr, "sha256:") {
		return SBOMSourceNone, "", false
	}
	hex := digestStr[7:]
	attTag := fmt.Sprintf("%s:sha256-%s.att", digestRef.Context().Name(), hex)
	attRef, err := name.ParseReference(attTag)
	if err != nil {
		return SBOMSourceNone, "", false
	}
	if _, err := remote.Head(attRef); err != nil {
		return SBOMSourceNone, "", false
	}
	return SBOMSourceFallback, attTag, true
}

// fetchBaseComponents downloads the SBOM artefact for the base image and
// parses it as CycloneDX JSON, returning the component list.
// Errors are non-fatal -- returns nil on failure.
func fetchBaseComponents(baseRef string) ([]cdx.Component, error) {
	ref, err := name.ParseReference(baseRef)
	if err != nil {
		return nil, err
	}

	digestRef, ok := ref.(name.Digest)
	if !ok {
		return nil, fmt.Errorf("not a digest ref")
	}

	idx, err := remote.Referrers(digestRef)
	if err != nil {
		return nil, err
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}

	sbomDesc := findSBOMDescriptor(manifest)
	if sbomDesc == nil {
		return nil, fmt.Errorf("no SBOM referrer found")
	}

	return fetchAndDecodeSBOM(digestRef, sbomDesc)
}

// findSBOMDescriptor searches an index manifest for the first SBOM referrer descriptor.
func findSBOMDescriptor(manifest *v1.IndexManifest) *v1.Descriptor {
	for i, desc := range manifest.Manifests {
		for _, at := range sbomArtifactTypes {
			if string(desc.ArtifactType) == at {
				return &manifest.Manifests[i]
			}
		}
	}
	return nil
}

// fetchAndDecodeSBOM fetches an SBOM image by descriptor and decodes its CycloneDX components.
func fetchAndDecodeSBOM(digestRef name.Digest, sbomDesc *v1.Descriptor) ([]cdx.Component, error) {
	sbomDigestRef := digestRef.Context().Digest(sbomDesc.Digest.String())
	sbomImg, err := remote.Image(sbomDigestRef)
	if err != nil {
		return nil, err
	}

	layers, err := sbomImg.Layers()
	if err != nil || len(layers) == 0 {
		return nil, fmt.Errorf("no layers in SBOM artefact")
	}

	rc, err := layers[0].Uncompressed()
	if err != nil {
		return nil, err
	}
	defer warnClose(rc, "sbom layer")

	// Parse as CycloneDX JSON
	bom := &cdx.BOM{}
	decoder := cdx.NewBOMDecoder(rc, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("decode base SBOM: %w", err)
	}

	if bom.Components == nil {
		return nil, nil
	}
	return *bom.Components, nil
}
