package integration_test

import (
	"context"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/testutil"
)

// TestImageFromStep_RunsByDigestRef exercises the imageFromStep base-image
// path end to end against the real engine: a step packs an image output, the
// producer wraps it via WrapImageOutputAsImage (which re-annotates and so
// stores it under a manifest digest distinct from the assembled digest), and a
// downstream step runs a container whose base is that producer image addressed
// by registry.WrapDigest -- exactly what resolveImageDigest hands the
// executor for an imageFromStep edge.
//
// This is the coverage gap behind the "container start: status 405" failure:
// executePack registered the handle with the pre-annotation assembled digest,
// not the engine-stored digest, so the downstream container-create referenced a
// nonexistent digest, create failed, and start hit the empty-id 405. The test
// asserts the container both creates and starts (exit 0), which only holds when
// the handle carries the digest the engine actually stored.
func TestImageFromStep_RunsByDigestRef(t *testing.T) {
	engine := testutil.RequireEngine(t)
	ctx := context.Background()

	ensureImage(t, engine, goImage)
	ensureImage(t, engine, staticBase)

	// 1. Produce an image output the way executePack does: pack, then wrap.
	binPath := buildTestBinary(t, engine)
	_, outRoot, _ := packTestImage(t, binPath)
	defer testutil.CloseLog(t, outRoot, "imageFrom outRoot")

	const laneID = "imagefrom-itest"
	const producerStep = "workspace"
	regClient := &registry.Client{Engine: engine}
	tag := registry.WrapTag(laneID, producerStep, primitive.DigestFromHex(
		"0000000000000000000000000000000000000000000000000000000000000001"))

	digest, _, wrapErr := regClient.WrapImageOutputAsImage(ctx, outRoot, "image.tar", tag, nil)
	if wrapErr != nil {
		t.Fatalf("wrap image output: %v", wrapErr)
	}

	// 2. Address the producer image exactly as resolveImageDigest does for an
	//    imageFromStep edge: the WrapDigest built from the engine-stored
	//    manifest digest, never the mutable tag (ADR-045/046).
	imageRef := registry.WrapDigest(laneID, producerStep, digest)
	t.Logf("imageFromStep base: %s", imageRef)

	// Deterministic invariant: the digest the handle carries must equal the
	// manifest digest the engine actually stored under the producer tag.
	// WrapImageOutputAsImage re-annotates the assembled image before loading it,
	// so the engine-stored digest differs from the assembled (pack) digest; a
	// handle built from the assembled digest would point at a manifest the engine
	// never stored. This compares against ImageInspect(tag).Digest and so does
	// not depend on the engine resolver's leniency for repo@digest refs.
	tagInfo, inspErr := engine.ImageInspect(ctx, tag)
	if inspErr != nil {
		t.Fatalf("inspect producer tag %s: %v", tag, inspErr)
	}
	if tagInfo.Digest != digest {
		t.Fatalf("handle digest %s != engine-stored digest %s: the imageFromStep base would be unresolvable",
			digest, tagInfo.Digest)
	}

	// 3. Run a held container whose base is that ref. The packed entrypoint is
	//    /app; it must create AND start (the 405 regression failed at start).
	opts := container.DefaultSecureOpts()
	opts.Image = primitive.ImageRef(imageRef)
	opts.Entrypoint = []string{"/app"}
	opts.Cmd = nil

	id, code, runErr := engine.ContainerRunHeld(ctx, opts, nil)
	if id != "" {
		defer func() {
			if rmErr := engine.ContainerRemove(ctx, id); rmErr != nil {
				t.Logf("WARN container remove: %v", rmErr)
			}
		}()
	}
	if runErr != nil {
		t.Fatalf("run held from imageFromStep base %s: %v", imageRef, runErr)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}
