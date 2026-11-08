package deploy

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/output"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/record"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/transport"
)

// artifactAnnotation names, on an SBOM referrer, the deploy artifacts map
// entry the document was cataloged for. Discovery convenience only,
// mirroring the statement annotation: the authoritative binding is the
// document digest pair sealed in the artifact's record (ADR-051 D9).
const artifactAnnotation = "dev.strike.artifact"

// executeRegistryDeploy publishes the image-arm artifact to the declared
// registry target and seals it (ADR-051 D2/D3/D4/D9): the control plane
// exports the image from the engine, checks the export against the produced
// content identity, writes it with remote.Write through the trust-anchored
// transport under the declared credential, catalogs the whole pushed image
// and every named region into CycloneDX and SPDX SBOMs, and attaches all
// documents as OCI referrers of the pushed manifest digest, each annotated
// with its artifacts-map name. The registry token was read and checked when
// the run started. The returned attach target carries the pushed
// descriptor, the transport and credential for the statement-bundle
// referrers, the validated push-connection identity for Sealed.ObservedPeers,
// the per-artifact SBOM digest sets for the sealed records, and the
// descriptor of every SBOM referrer pushed, which the read-after-write
// confirms (ADR-051 amendment 2026-11-08).
func (d *Deployer) executeRegistryDeploy(ctx context.Context, m lane.DeployRegistry, state *lane.Runtime) (*attachTarget, error) {
	imageName, imageRef, err := selectImageArm(d.ArtifactRefs)
	if err != nil {
		return nil, fmt.Errorf("registry deploy: %w", err)
	}
	handle, err := state.Resolve(lane.OutputRef{Step: imageRef.Step})
	if err != nil {
		return nil, fmt.Errorf("registry deploy: resolve artifact: %w", err)
	}
	ih, ok := handle.(output.ImageHandle)
	if !ok {
		return nil, fmt.Errorf("registry deploy: artifact %q is not an image output", imageName)
	}

	tarBytes, err := registry.SaveImage(ctx, d.Engine, ih.Ref)
	if err != nil {
		return nil, fmt.Errorf("registry deploy: %w", err)
	}
	img, err := registry.ImageFromOCITar(tarBytes)
	if err != nil {
		return nil, fmt.Errorf("registry deploy: %w", err)
	}

	if verifyErr := verifyExportedImage(img, ih.ConfigDigest); verifyErr != nil {
		return nil, fmt.Errorf("registry deploy: %w", verifyErr)
	}

	token, ok := d.RegistryTokens[string(m.Target.Address.Authority())]
	if !ok {
		return nil, fmt.Errorf("registry deploy: no registry token was read for target %s", m.Target.Address.Authority())
	}
	rt, obs, err := newRegistryTransport(m.Target, d.Dialer, token)
	if err != nil {
		return nil, fmt.Errorf("registry deploy: %w", err)
	}
	client := registryClient{rt: rt, token: token}
	subject, err := payloadDescriptor(img)
	if err != nil {
		return nil, fmt.Errorf("registry deploy: %w", err)
	}

	repo := string(m.Target.Address.Authority()) + "/" + string(m.Target.Name)
	if pushErr := pushByDigest(ctx, repo, subject.Digest.String(), img, client); pushErr != nil {
		return nil, fmt.Errorf("registry deploy: push payload: %w", pushErr)
	}

	sboms := map[primitive.Identifier]record.SBOMSet{}
	imgSet, imgReferrers, sbomErr := pushImageSBOM(ctx, repo, subject, img, client, imageName)
	if sbomErr != nil {
		return nil, fmt.Errorf("registry deploy: %w", sbomErr)
	}
	sboms[imageName] = imgSet
	regionSets, regionReferrers, regionErr := d.regionSBOMs(ctx, repo, subject, client, state)
	if regionErr != nil {
		return nil, fmt.Errorf("registry deploy: %w", regionErr)
	}
	maps.Copy(sboms, regionSets)

	id, resolved, ok := obs.get()
	if !ok {
		return nil, fmt.Errorf("registry deploy: no validated push connection observed")
	}
	return &attachTarget{
		subject:    subject,
		client:     client,
		observed:   ObservedTLS{Type: "https", ServerCertFingerprint: id.LeafFingerprint},
		resolved:   resolved,
		sboms:      sboms,
		referrers:  slices.Concat(imgReferrers, regionReferrers),
		ref:        repo,
		authority:  m.Target.Address.Authority(),
		repository: m.Target.Name,
	}, nil
}

// selectImageArm returns the single image-arm entry of the artifacts map --
// the pushed subject (ADR-051 D9). Lane validation guarantees exactly one;
// this re-check is the last structural guard before the push.
func selectImageArm(refs map[primitive.Identifier]lane.ArtifactRef) (primitive.Identifier, lane.ArtifactRef, error) {
	var artName primitive.Identifier
	var found lane.ArtifactRef
	n := 0
	for _, k := range slices.Sorted(maps.Keys(refs)) {
		if refs[k].Output == nil {
			artName, found = k, refs[k]
			n++
		}
	}
	if n != 1 {
		return "", lane.ArtifactRef{}, fmt.Errorf("exactly one image-arm artifacts entry required, got %d", n)
	}
	return artName, found, nil
}

// checkReproducedBy is the reproduction gate of a registry deploy (ADR-009):
// when the method names a reproducedBy step, the manifest digest of that
// step's image must equal the image arm's. Both digests must be ones the
// control plane computed when it assembled and loaded the image in this run;
// a handle without a produced config digest was restored from the engine
// store and is refused rather than compared. Lane validation admits exactly
// one image arm. Any other method, or a registry deploy without
// reproducedBy, passes. Execute runs this first, so a mismatch stops the
// deploy before anything is captured, pushed or signed. A passing gate logs
// both steps and the digest they agree on.
func checkReproducedBy(method lane.DeployMethod, refs map[primitive.Identifier]lane.ArtifactRef, state *lane.Runtime) error {
	reg, ok := method.(lane.DeployRegistry)
	if !ok || reg.ReproducedBy == nil {
		return nil
	}
	var arm primitive.Identifier
	for _, ref := range refs {
		if ref.Output == nil {
			arm = ref.Step
		}
	}
	steps := [2]primitive.Identifier{arm, *reg.ReproducedBy}
	var digests [2]primitive.Digest
	for i, id := range steps {
		h, err := state.Resolve(lane.OutputRef{Step: id})
		if err != nil {
			return fmt.Errorf("reproducedBy: %w", err)
		}
		ih, isImage := h.(output.ImageHandle)
		if !isImage || ih.ConfigDigest == "" {
			return fmt.Errorf("reproducedBy: step %q holds no image produced in this run", id)
		}
		digest, err := output.ManifestDigest(ih)
		if err != nil {
			return fmt.Errorf("reproducedBy: %w", err)
		}
		digests[i] = digest
	}
	if digests[0] != digests[1] {
		return fmt.Errorf("reproducedBy: step %q built %s but step %q built %s; the image is not reproducible",
			steps[0], digests[0], steps[1], digests[1])
	}
	log.Printf("GATE   reproducedBy: %s and %s built %s", steps[0], steps[1], digests[0])
	return nil
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

// pushImageSBOM flattens the pushed image, generates the CycloneDX and SPDX
// SBOMs over the pushed manifest digest -- the image arm's whole-image
// catalog (ADR-051 D3/D9) -- and pushes both as OCI referrers of subject,
// annotated with the image arm's artifacts name. It returns what
// pushSBOMPair returns.
func pushImageSBOM(ctx context.Context, repo string, subject v1.Descriptor, img v1.Image, client registryClient, artName primitive.Identifier) (record.SBOMSet, []v1.Descriptor, error) {
	fsys, err := flattenImageToFS(img)
	if err != nil {
		return record.SBOMSet{}, nil, fmt.Errorf("flatten payload: %w", err)
	}
	subjectDigest := primitive.Digest(subject.Digest.String())
	return pushSBOMPair(ctx, repo, subject, client, artName, fsys, subjectDigest)
}

// regionSBOMs catalogs every file and directory region of the artifacts map
// (ADR-051 D9): each region's producer image is exported once, the region's
// layer is selected and content-checked against the handle's diff_id
// (checked courier, ADR-051 D4), the layer content is read at the output's
// own coordinates, and the region's SBOM pair is pushed as referrers of the
// pushed subject. Regions run in sorted name order so the referrer writes
// are deterministic. It returns the SBOM digest set of every region and the
// descriptor of every SBOM referrer pushed.
func (d *Deployer) regionSBOMs(ctx context.Context, repo string, subject v1.Descriptor, client registryClient, state *lane.Runtime) (map[primitive.Identifier]record.SBOMSet, []v1.Descriptor, error) {
	sets := map[primitive.Identifier]record.SBOMSet{}
	var referrers []v1.Descriptor
	exported := map[string][]byte{}
	for _, artName := range slices.Sorted(maps.Keys(d.ArtifactRefs)) {
		ref := d.ArtifactRefs[artName]
		if ref.Output == nil {
			continue
		}
		set, pushed, err := d.regionSBOM(ctx, repo, subject, client, state, artName, ref, exported)
		if err != nil {
			return nil, nil, fmt.Errorf("region %q: %w", artName, err)
		}
		sets[artName] = set
		referrers = append(referrers, pushed...)
	}
	return sets, referrers, nil
}

// regionSBOM catalogs one region: resolve the file handle, export the
// producer image (deduplicated across regions of the same producer through
// exported), select and content-check the layer, read it at the output's own
// coordinates, and push the SBOM pair under the region's diff_id subject. It
// returns what pushSBOMPair returns.
func (d *Deployer) regionSBOM(ctx context.Context, repo string, subject v1.Descriptor, client registryClient, state *lane.Runtime, artName primitive.Identifier, ref lane.ArtifactRef, exported map[string][]byte) (record.SBOMSet, []v1.Descriptor, error) {
	handle, err := state.Resolve(lane.OutputRef{Step: ref.Step, Output: *ref.Output})
	if err != nil {
		return record.SBOMSet{}, nil, err
	}
	fh, ok := handle.(output.FileHandle)
	if !ok {
		return record.SBOMSet{}, nil, fmt.Errorf("not a file output")
	}
	tarBytes, cached := exported[fh.Ref]
	if !cached {
		saved, saveErr := registry.SaveImage(ctx, d.Engine, fh.Ref)
		if saveErr != nil {
			return record.SBOMSet{}, nil, saveErr
		}
		exported[fh.Ref] = saved
		tarBytes = saved
	}
	layerBytes, err := registry.OutputLayer(tarBytes, fh.LayerDiffID)
	if err != nil {
		return record.SBOMSet{}, nil, err
	}
	out := d.Lane.Output(ref.Step, *ref.Output)
	if out == nil {
		return record.SBOMSet{}, nil, fmt.Errorf("output %s.%s not declared", ref.Step, *ref.Output)
	}
	fsys, err := fsFromTarBuffer(layerBytes, lane.OutputContentPrefix(*out).String())
	if err != nil {
		return record.SBOMSet{}, nil, err
	}
	return pushSBOMPair(ctx, repo, subject, client, artName, fsys, fh.LayerDiffID)
}

// pushSBOMPair catalogs fsys under subjectDigest, pushes the CycloneDX and
// SPDX documents as OCI referrers of subject -- each annotated with the
// artifacts-map name it belongs to -- and returns both document digests for
// the artifact's sealed record (ADR-051 D9) and both referrer descriptors
// for the read-after-write (ADR-051 amendment 2026-11-08).
func pushSBOMPair(ctx context.Context, repo string, subject v1.Descriptor, client registryClient, artName primitive.Identifier, fsys fs.FS, subjectDigest primitive.Digest) (record.SBOMSet, []v1.Descriptor, error) {
	cdxBytes, spdxBytes, err := GenerateImageSBOM(fsys, subjectDigest, clock.Reproducible())
	if err != nil {
		return record.SBOMSet{}, nil, fmt.Errorf("sbom: %w", err)
	}
	referrers := make([]v1.Descriptor, 0, 2)
	for _, doc := range []struct {
		mediaType string
		content   []byte
	}{
		{mediaType: "application/vnd.cyclonedx+json", content: cdxBytes},
		{mediaType: "application/spdx+json", content: spdxBytes},
	} {
		art, artErr := registry.ArtifactImage(doc.content, doc.mediaType, subject, map[string]string{artifactAnnotation: string(artName)})
		if artErr != nil {
			return record.SBOMSet{}, nil, fmt.Errorf("sbom artifact: %w", artErr)
		}
		desc, dErr := partial.Descriptor(art)
		if dErr != nil {
			return record.SBOMSet{}, nil, fmt.Errorf("sbom artifact digest: %w", dErr)
		}
		if pushErr := pushByDigest(ctx, repo, desc.Digest.String(), art, client); pushErr != nil {
			return record.SBOMSet{}, nil, fmt.Errorf("attach sbom to %s: %w", subject.Digest, pushErr)
		}
		referrers = append(referrers, *desc)
	}
	return record.SBOMSet{CycloneDX: docDigest(cdxBytes), SPDX: docDigest(spdxBytes)}, referrers, nil
}

// docDigest is the prefixed sha256 content digest of one SBOM document, the
// value the sealed artifact record binds the referrer to (ADR-051 D9).
func docDigest(doc []byte) primitive.Digest {
	return primitive.DigestFromHex(hex.EncodeToString(sha256Sum(doc)))
}

// pushByDigest writes img to repo at the given manifest digest through the
// client's transport, which carries the credential. A manifest with a
// subject requires the registry's referrers API: the referrers tag fallback
// is refused, so no write creates a tag (ADR-058). The error is scrubbed of
// the token.
func pushByDigest(ctx context.Context, repo, digest string, img v1.Image, client registryClient) error {
	dst, err := name.NewDigest(repo + "@" + digest)
	if err != nil {
		return fmt.Errorf("target reference %q: %w", repo+"@"+digest, err)
	}
	return scrub(remote.Write(dst, img, remote.WithTransport(client.rt), remote.WithReferrersTagFallback(false), remote.WithContext(ctx)), client.token)
}

// registryClient is what every write to the declared registry target
// carries: the trust-anchored transport, which presents the registry token
// the target's credential names as the bearer (ADR-058 D2, amendment
// 2026-11-08), and the token itself, which scrub removes from errors.
type registryClient struct {
	rt    http.RoundTripper
	token lane.SecretString
}

// ReadRegistryTokens reads the registry token of every registry deploy of p
// once, when the run starts, keyed by the target's written authority, and
// checks each before any use through CheckRegistryToken, fail-closed: its
// lifetime stays within the bound, and its audience does not contain the
// lane's oidc audience, because a token minted for Fulcio is never presented
// to a registry (ADR-058 D3, amendment 2026-11-08). Lane validation gives the
// deploy targets of one authority one token, so each authority is read once.
func ReadRegistryTokens(p *lane.Lane, root *os.Root) (map[string]lane.SecretString, error) {
	tokens := map[string]lane.SecretString{}
	for _, s := range p.Steps {
		if s.Deploy == nil {
			continue
		}
		reg, ok := s.Deploy.Method.(lane.DeployRegistry)
		if !ok {
			continue
		}
		auth := string(reg.Target.Address.Authority())
		if _, done := tokens[auth]; done {
			continue
		}
		cred := reg.Target.Credential.Token
		token, err := lane.ReadSecret(p.Secrets[cred], root)
		if err == nil {
			err = CheckRegistryToken(token, p.OIDC.Audience)
		}
		if err != nil {
			return nil, fmt.Errorf("deploy step %q: registry token %q: %w", s.ID, cred, err)
		}
		tokens[auth] = token
	}
	return tokens, nil
}

// scrub removes the token from err's text. go-containerregistry carries a
// registry's error body into the error it returns, and that body is text the
// registry controls; the token must not reach a log through it (ADR-058 D1).
func scrub(err error, token lane.SecretString) error {
	if err == nil || token.Expose() == "" || !strings.Contains(err.Error(), token.Expose()) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token.Expose(), token.String()))
}

// pushIdentityCapture records the first validated push-connection identity
// and the union of the DoT answers across every push connection, the
// resolution the observed peer carries like a mediated peer does.
type pushIdentityCapture struct {
	resolved []netip.Addr
	id       transport.ConnectionIdentity
	mu       sync.Mutex
	ok       bool
}

func (c *pushIdentityCapture) record(vc *transport.VerifiedConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ok {
		c.id = vc.Identity()
		c.ok = true
	}
	for _, a := range vc.Resolved() {
		c.resolved = appendUnique(c.resolved, a)
	}
}

func (c *pushIdentityCapture) get() (transport.ConnectionIdentity, []netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id, c.resolved, c.ok
}

// newRegistryTransport builds the trust-anchored round tripper every write
// to the declared registry target dials through: the payload push, the SBOM
// referrers, and the statement-bundle referrers. It carries token as the
// bearer through registry.CredentialTransport, so a redirect of any write
// fails (ADR-058 amendment 2026-11-08). Enforcement is structural
// (ADR-051 D4): the declared target name is resolved through the lane's own
// DoT resolver and the TLS dial verifies the declared endpoint.Certificate anchor
// against that name, a dial to any address other than the declared authority
// is rejected -- a redirect off the target therefore fails instead of being
// followed -- and a plaintext dial is rejected outright. The identity
// observed on the verified handshake with the one permitted host is captured
// for Sealed.ObservedPeers: the final dialed host is the attested host.
func newRegistryTransport(target lane.DeployRegistryTarget, dialer *transport.Dialer, token lane.SecretString) (http.RoundTripper, *pushIdentityCapture, error) {
	if target.Address.Host == "" {
		return nil, nil, fmt.Errorf("registry target: host required")
	}
	if target.Name == "" {
		return nil, nil, fmt.Errorf("registry target: name required")
	}
	if target.Trust.Cert == "" {
		return nil, nil, fmt.Errorf("registry target: trust required")
	}
	if dialer == nil {
		return nil, nil, fmt.Errorf("registry target: dialer required")
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
			vc, dialErr := dialer.DialPeer(ctx, dialAddr.Host, *dialAddr.Port, target.Trust)
			if dialErr != nil {
				return nil, dialErr
			}
			capture.record(vc)
			return vc.Conn(), nil
		},
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("registry push: plaintext dial to %q rejected; the target is https-only", addr)
		},
	}
	authority := string(target.Address.Authority())
	return transport.HTTPSOnly(registry.CredentialTransport(base, authority, token)), capture, nil
}
