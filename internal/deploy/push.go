package deploy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/output"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/transport"
)

// executeRegistryDeploy publishes the resolved artifacts step image to the
// declared registry target and seals it (ADR-051 D2/D3/D4): the control
// plane exports the image from the engine, writes it with remote.Write
// through the trust-anchored transport, catalogs the pushed bytes into
// CycloneDX and SPDX SBOMs over the pushed manifest digest, and attaches
// both as OCI referrers of that digest. The returned attach target carries
// the pushed descriptor, the transport for the statement-bundle referrers,
// and the validated push-connection identity for Sealed.ObservedPeers.
func (d *Deployer) executeRegistryDeploy(ctx context.Context, m lane.DeployRegistry, state *lane.Runtime) (*attachTarget, error) {
	if len(d.ArtifactRefs) != 1 {
		return nil, fmt.Errorf("registry deploy: exactly one artifacts step image required, got %d", len(d.ArtifactRefs))
	}
	var ref lane.OutputRef
	for _, r := range d.ArtifactRefs {
		ref = r
	}
	handle, err := state.Resolve(ref)
	if err != nil {
		return nil, fmt.Errorf("registry deploy: resolve artifact: %w", err)
	}
	ih, ok := handle.(output.ImageHandle)
	if !ok {
		return nil, fmt.Errorf("registry deploy: artifact %q is not an image output", ref.Ref())
	}

	tarBytes, err := registry.SaveImage(ctx, d.Engine, ih.Ref)
	if err != nil {
		return nil, fmt.Errorf("registry deploy: %w", err)
	}
	img, cleanup, err := registry.ExtractMainImage(bytes.NewReader(tarBytes))
	if err != nil {
		return nil, fmt.Errorf("registry deploy: %w", err)
	}
	defer cleanup()

	if verifyErr := verifyExportedImage(img, ih.ConfigDigest); verifyErr != nil {
		return nil, fmt.Errorf("registry deploy: %w", verifyErr)
	}

	rt, obs, err := newRegistryTransport(m.Target)
	if err != nil {
		return nil, fmt.Errorf("registry deploy: %w", err)
	}
	subject, err := payloadDescriptor(img)
	if err != nil {
		return nil, fmt.Errorf("registry deploy: %w", err)
	}

	repo := string(m.Target.Address.Authority()) + "/" + string(m.Target.Name)
	if pushErr := pushByDigest(ctx, repo, subject.Digest.String(), img, rt); pushErr != nil {
		return nil, fmt.Errorf("registry deploy: push payload: %w", pushErr)
	}

	if sbomErr := pushSBOMReferrers(ctx, repo, subject, img, rt); sbomErr != nil {
		return nil, fmt.Errorf("registry deploy: %w", sbomErr)
	}

	id, ok := obs.get()
	if !ok {
		return nil, fmt.Errorf("registry deploy: no validated push connection observed")
	}
	return &attachTarget{
		subject:    subject,
		rt:         rt,
		observed:   ObservedTLS{Type: "https", ServerCertFingerprint: id.LeafFingerprint},
		ref:        repo,
		authority:  m.Target.Address.Authority(),
		repository: m.Target.Name,
	}, nil
}

// verifyExportedImage checks an engine-exported image against the content
// identity the control plane computed when it produced that image. The engine
// re-encodes layer blobs on export, so the produced manifest digest does not
// survive the round trip; the config blob does (ADR-046). The config commits to
// rootfs.diff_ids and each diff_id is the hash of its layer's uncompressed
// content, so checking the config digest and then recomputing every layer's
// diff_id against that config binds all exported bytes to an anchor the control
// plane holds. This is what makes the engine a checked courier rather than an
// unexamined witness on the sealing path (ADR-051 D4).
func verifyExportedImage(img v1.Image, produced primitive.Digest) error {
	if produced == "" {
		return fmt.Errorf("artifact carries no produced config digest; the deploy artifact must be produced in this run")
	}
	configHash, err := img.ConfigName()
	if err != nil {
		return fmt.Errorf("exported config digest: %w", err)
	}
	if configHash.String() != produced.String() {
		return fmt.Errorf("exported config digest %s does not match the produced config digest %s", configHash, produced)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("exported config file: %w", err)
	}
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("exported layers: %w", err)
	}
	if len(layers) != len(cfg.RootFS.DiffIDs) {
		return fmt.Errorf("exported image has %d layers, its config declares %d diff ids", len(layers), len(cfg.RootFS.DiffIDs))
	}
	for i, l := range layers {
		diffID, diffErr := l.DiffID()
		if diffErr != nil {
			return fmt.Errorf("exported layer %d diff id: %w", i, diffErr)
		}
		if diffID != cfg.RootFS.DiffIDs[i] {
			return fmt.Errorf("exported layer %d content hashes to %s, its config declares %s", i, diffID, cfg.RootFS.DiffIDs[i])
		}
	}
	return nil
}

// payloadDescriptor computes the pushed-subject descriptor of the exported
// image. The engine save re-encodes on export, so this digest differs from the
// produced manifest digest by construction; both enter the attestation, the
// pushed one as sealed.pushed and the produced one as the artifact record
// (ADR-051 D4/D6).
func payloadDescriptor(img v1.Image) (v1.Descriptor, error) {
	digest, err := img.Digest()
	if err != nil {
		return v1.Descriptor{}, fmt.Errorf("payload digest: %w", err)
	}
	size, err := img.Size()
	if err != nil {
		return v1.Descriptor{}, fmt.Errorf("payload size: %w", err)
	}
	mediaType, err := img.MediaType()
	if err != nil {
		return v1.Descriptor{}, fmt.Errorf("payload media type: %w", err)
	}
	return v1.Descriptor{MediaType: mediaType, Digest: digest, Size: size}, nil
}

// pushSBOMReferrers flattens the pushed image, generates the CycloneDX and
// SPDX SBOMs over the pushed manifest digest, and pushes both as OCI
// referrers of subject through rt.
func pushSBOMReferrers(ctx context.Context, repo string, subject v1.Descriptor, img v1.Image, rt http.RoundTripper) error {
	fsys, err := flattenImageToFS(img)
	if err != nil {
		return fmt.Errorf("flatten payload: %w", err)
	}
	cdxBytes, spdxBytes, err := GenerateImageSBOM(fsys, subject.Digest.String(), clock.Reproducible())
	if err != nil {
		return fmt.Errorf("sbom: %w", err)
	}
	for _, doc := range []struct {
		mediaType string
		content   []byte
	}{
		{mediaType: "application/vnd.cyclonedx+json", content: cdxBytes},
		{mediaType: "application/spdx+json", content: spdxBytes},
	} {
		art, artErr := registry.ArtifactImage(doc.content, doc.mediaType, subject, nil)
		if artErr != nil {
			return fmt.Errorf("sbom artifact: %w", artErr)
		}
		artDigest, dErr := art.Digest()
		if dErr != nil {
			return fmt.Errorf("sbom artifact digest: %w", dErr)
		}
		if pushErr := pushByDigest(ctx, repo, artDigest.String(), art, rt); pushErr != nil {
			return fmt.Errorf("attach sbom: %w", pushErr)
		}
	}
	return nil
}

// pushByDigest writes img to repo at the given manifest digest through rt.
func pushByDigest(ctx context.Context, repo, digest string, img v1.Image, rt http.RoundTripper) error {
	dst, err := name.NewDigest(repo + "@" + digest)
	if err != nil {
		return fmt.Errorf("target reference %q: %w", repo+"@"+digest, err)
	}
	return remote.Write(dst, img, remote.WithTransport(rt), remote.WithContext(ctx))
}

// pushIdentityCapture records the first validated push-connection identity.
type pushIdentityCapture struct {
	id transport.ConnectionIdentity
	mu sync.Mutex
	ok bool
}

func (c *pushIdentityCapture) record(id transport.ConnectionIdentity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ok {
		c.id = id
		c.ok = true
	}
}

func (c *pushIdentityCapture) get() (transport.ConnectionIdentity, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id, c.ok
}

// httpsOnlyTransport forces every request onto https before it reaches the
// dial layer. go-containerregistry resolves localhost-style registries to
// the http scheme on its own; the deploy path owns its addressing (ADR-051
// D4), so the scheme is pinned here and the plaintext dial below stays a
// structurally unreachable rejection.
type httpsOnlyTransport struct {
	inner http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t httpsOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.URL.Scheme = "https"
	return t.inner.RoundTrip(r)
}

// newRegistryTransport builds the trust-anchored round tripper every write
// to the declared registry target dials through: the payload push, the SBOM
// referrers, and the statement-bundle referrers. Enforcement is structural
// (ADR-051 D4): the TLS dial verifies the declared endpoint.Trust anchor, a
// dial to any address other than the declared authority is rejected -- a
// redirect off the target therefore fails instead of being followed -- and a
// plaintext dial is rejected outright. The identity observed on the verified
// handshake with the one permitted host is captured for
// Sealed.ObservedPeers: the final dialed host is the attested host.
func newRegistryTransport(target lane.DeployRegistryTarget) (http.RoundTripper, *pushIdentityCapture, error) {
	if target.Address.Host == "" {
		return nil, nil, fmt.Errorf("registry target: host required")
	}
	if target.Name == "" {
		return nil, nil, fmt.Errorf("registry target: name required")
	}
	if target.Trust == nil {
		return nil, nil, fmt.Errorf("registry target: trust required")
	}
	dialAddr := target.Address
	if dialAddr.Port == nil {
		port := primitive.Port(443)
		dialAddr.Port = &port
	}
	expected := string(dialAddr.Authority())
	capture := &pushIdentityCapture{}
	base := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			if addr != expected {
				return nil, fmt.Errorf("registry push: dial %q outside the declared target %q rejected", addr, expected)
			}
			vc, dialErr := transport.DialVerified(ctx, dialAddr, target.Trust)
			if dialErr != nil {
				return nil, dialErr
			}
			capture.record(vc.Identity())
			return vc.Conn(), nil
		},
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("registry push: plaintext dial to %q rejected; the target is https-only", addr)
		},
	}
	return httpsOnlyTransport{inner: base}, capture, nil
}
