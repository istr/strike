package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/primitive"
)

// refNameAnnotation is the OCI image-layout annotation naming the image a
// layout index entry describes. The engine takes it as the store name of the
// loaded image, exactly as a pull by that name would record it.
const refNameAnnotation = "org.opencontainers.image.ref.name"

// fetched is what fetchByDigest hands to the layout writer.
type fetched struct {
	image    v1.Image      // the image of the engine's platform
	top      v1.Descriptor // the object the layout index names
	rawIndex []byte        // the index bytes when top is an index, else nil
}

// EnsureImage makes a digest-pinned external image resolvable in the engine
// store under its declared reference, unless the store resolves it already.
// The control plane fetches the index or manifest the declared digest names
// and, for an index, the one entry of the engine's platform; every byte is
// verified against its digest as it is read, so the controller recomputes
// the content hash of the inbound image (ADR-030, ADR-037 D1). The bytes are
// streamed into the engine as an OCI image layout whose index names the
// declared digest and carries the declared reference as its ref.name, so the
// store names the image as a pull by that reference would, and the step
// executes the declared reference unchanged (ADR-045). The engine never
// pulls. A verification failure aborts the stream before the layout is
// complete, so the engine imports nothing.
func (c *Client) EnsureImage(ctx context.Context, ref primitive.ImageRef) error {
	declared := string(ref)
	present, err := c.Engine.ImageExists(ctx, declared)
	if err != nil {
		return fmt.Errorf("image %s: exists: %w", ref, err)
	}
	if present {
		return nil
	}
	platform, err := EnginePlatform(c.Engine)
	if err != nil {
		return fmt.Errorf("image %s: %w", ref, err)
	}
	log.Printf("FETCH  %s", ref)
	f, err := fetchByDigest(ctx, ref, platform)
	if err != nil {
		return fmt.Errorf("image %s: fetch: %w", ref, err)
	}
	configHash, err := f.image.ConfigName()
	if err != nil {
		return fmt.Errorf("image %s: config digest: %w", ref, err)
	}
	f.top.Annotations = map[string]string{refNameAnnotation: declared}

	pr, pw := io.Pipe()
	written := make(chan error, 1)
	go func() {
		wErr := writeOCITar(pw, f.image, f.top, f.rawIndex)
		pw.CloseWithError(wErr)
		written <- wErr
	}()
	_, loadErr := c.Engine.ImageLoad(ctx, pr)
	closer.Warn(pr, "image load stream")
	if wErr := <-written; wErr != nil && !errors.Is(wErr, io.ErrClosedPipe) {
		return fmt.Errorf("image %s: %w", ref, wErr)
	}
	if loadErr != nil {
		return fmt.Errorf("image %s: load: %w", ref, loadErr)
	}

	info, err := c.Engine.ImageInspect(ctx, declared)
	if err != nil {
		return fmt.Errorf("image %s: not resolvable after load: %w", ref, err)
	}
	if info.ID != configHash.Hex {
		return fmt.Errorf("image %s: store resolves the reference to config %s, fetched config is %s",
			ref, info.ID, configHash.Hex)
	}
	return nil
}

// EnginePlatform is the platform the engine reported through Info. It
// selects the index entry to fetch, for a step image and for a pack base
// alike, and carries no trust: a wrong platform yields an image that does not
// start, never an image that passes the digest check.
func EnginePlatform(e container.Engine) (v1.Platform, error) {
	id := e.Identity()
	if id == nil || id.Runtime == nil || id.Runtime.OS == "" || id.Runtime.Arch == "" {
		return v1.Platform{}, errors.New("engine platform unknown: engine info not read")
	}
	return v1.Platform{OS: id.Runtime.OS, Architecture: id.Runtime.Arch, Variant: id.Runtime.Variant}, nil
}

// FetchImage resolves a digest-pinned reference to the image of platform,
// verified as fetchByDigest verifies it: the index or manifest against the
// declared digest on fetch, every blob as it is read. It is the pack base
// fetch, so a lane-generated image is assembled on the base of the platform
// that runs it (ADR-046).
func FetchImage(ctx context.Context, ref primitive.ImageRef, platform v1.Platform) (v1.Image, error) {
	f, err := fetchByDigest(ctx, ref, platform)
	if err != nil {
		return nil, err
	}
	return f.image, nil
}

// fetchByDigest resolves ref at its registry. go-containerregistry verifies
// the object the digest names against the digest on fetch and every blob of
// the returned image against its descriptor as it is read; the registry's
// identity contributes nothing (ADR-030). For an index, the entry of
// platform is selected and the raw index bytes are returned for the layout.
func fetchByDigest(ctx context.Context, ref primitive.ImageRef, platform v1.Platform) (fetched, error) {
	declared := string(ref)
	nameRef, err := name.ParseReference(declared)
	if err != nil {
		return fetched{}, fmt.Errorf("parse reference: %w", err)
	}
	if _, ok := nameRef.(name.Digest); !ok {
		return fetched{}, errors.New("reference is not pinned by digest")
	}
	desc, err := remote.Get(nameRef, remote.WithContext(ctx))
	if err != nil {
		return fetched{}, err
	}
	top := v1.Descriptor{MediaType: desc.MediaType, Digest: desc.Digest, Size: desc.Size}
	if !desc.MediaType.IsIndex() {
		img, imgErr := desc.Image()
		if imgErr != nil {
			return fetched{}, imgErr
		}
		return fetched{top: top, image: img}, nil
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return fetched{}, err
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return fetched{}, err
	}
	child, err := selectPlatform(manifest.Manifests, platform)
	if err != nil {
		return fetched{}, err
	}
	img, err := idx.Image(child.Digest)
	if err != nil {
		return fetched{}, err
	}
	return fetched{top: top, rawIndex: desc.Manifest, image: img}, nil
}

// selectPlatform returns the one index entry for want: os and architecture
// must be equal; a single such entry is taken whatever its variant, several
// are decided by an exact variant match. Zero or several remaining entries
// are an error, never a guess.
func selectPlatform(entries []v1.Descriptor, want v1.Platform) (v1.Descriptor, error) {
	var byArch, byVariant []v1.Descriptor
	for _, d := range entries {
		if d.Platform == nil || d.Platform.OS != want.OS || d.Platform.Architecture != want.Architecture {
			continue
		}
		byArch = append(byArch, d)
		if d.Platform.Variant == want.Variant {
			byVariant = append(byVariant, d)
		}
	}
	switch {
	case len(byArch) == 1:
		return byArch[0], nil
	case len(byVariant) == 1:
		return byVariant[0], nil
	case len(byArch) == 0:
		return v1.Descriptor{}, fmt.Errorf("index has no manifest for %s/%s", want.OS, want.Architecture)
	default:
		return v1.Descriptor{}, fmt.Errorf("index has %d manifests for %s/%s and variant %q does not decide",
			len(byArch), want.OS, want.Architecture, want.Variant)
	}
}
