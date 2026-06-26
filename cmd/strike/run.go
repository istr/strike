package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/front"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/spec"
	"github.com/istr/strike/internal/transport"
)

// runState holds accumulated state across steps during a lane execution.
type runState struct {
	specHashes map[string]lane.DigestRef
	// imageFromRefs maps a consumer step name to the producer's
	// content-addressed local digest reference
	// (localhost/strike/<lane>/<step>@sha256:<D>), populated by
	// resolveImageDigest when the consumer has an image_from edge.
	// Consumed by executeContainerStep to override Step.Image in the
	// executor invocation without mutating the parsed Lane. The base is
	// executed only by this digest reference, never by a mutable tag
	// (ADR-045).
	imageFromRefs map[string]string
}

func newRunState() *runState {
	return &runState{
		specHashes:    map[string]lane.DigestRef{},
		imageFromRefs: map[string]string{},
	}
}

// runContext bundles everything needed to execute steps.
type runContext struct {
	ctx            context.Context
	engine         container.Engine
	state          *runState
	laneState      *lane.State // artifact graph for deploy attestations
	regClient      *registry.Client
	engineID       *container.EngineIdentity
	ca             *transport.EphemeralCA
	front          *front.Front
	upstreamLook   capsule.UpstreamLookupFunc
	lane           *lane.Lane
	laneDigest     lane.DigestRef
	dag            *lane.DAG
	stepPorts      map[string]capsule.HostPorts       // mediated step name -> host ports
	networkRecords map[string]capsule.Records         // step name -> records
	capsules       map[string]*capsule.NetworkCapsule // run-step name -> pre-built capsule
	laneRoot       *os.Root
	trust          trustVolumes
	laneDir        string
	resolverID     transport.ConnectionIdentity
}

func (rc *runContext) runStep(stepID string) error {
	step := rc.dag.Steps[stepID]
	safeName := sanitizeForLog(stepID)

	// Timeout resolution: explicit step value > lane-wide default > hard floor.
	var rawTimeout *spec.Duration
	switch {
	case step.Timeout != nil:
		rawTimeout = step.Timeout
	case rc.lane.Defaults != nil:
		d := spec.Duration(rc.lane.Defaults.Timeout)
		rawTimeout = &d
	}
	timeout, err := lane.ParseDuration(rawTimeout, 10*clock.Minute)
	if err != nil {
		return fmt.Errorf("%s: invalid timeout %q: %w", safeName, *rawTimeout, err)
	}
	ctx, cancel := context.WithTimeout(rc.ctx, timeout)
	defer cancel()

	// Deploy steps have their own execution model -- no image resolution,
	// no spec hash caching. Dispatch early.
	if step.Deploy != nil {
		return rc.executeDeploy(ctx, step, stepID, safeName)
	}

	imageDigest, err := rc.resolveImageDigest(ctx, step, safeName)
	if err != nil {
		return err
	}
	specHash, tag, err := rc.computeSpecHash(step, stepID, imageDigest)
	if err != nil {
		return err
	}

	cached, cacheErr := rc.checkCache(ctx, step, stepID, safeName, specHash)
	if cacheErr != nil {
		return cacheErr
	}
	if cached {
		return nil
	}

	log.Printf("RUN    %s", safeName)

	if step.Pack != nil {
		return rc.executePack(ctx, step, stepID, safeName)
	}
	return rc.executeContainerStep(ctx, step, stepID, safeName, tag)
}

func (rc *runContext) executeDeploy(ctx context.Context, step *lane.Step, stepID, safeName string) error {
	log.Printf("DEPLOY %s", safeName)

	artifactRefs := make(map[string]string)
	for _, e := range rc.dag.DeployEdges[stepID] {
		var out spec.Identifier
		if !e.Image {
			out = e.FromOutput.ID
		}
		artifactRefs[e.ArtifactName] = lane.OutputRef{Step: e.FromStep.ID, Output: out}.Ref()
	}

	d := &deploy.Deployer{
		Engine:          rc.engine,
		EngineID:        rc.engineID,
		ResolverID:      &rc.resolverID,
		DAG:             rc.dag,
		OIDC:            rc.lane.OIDC,
		Keyless:         rc.lane.Keyless,
		BaseSBOMSigners: rc.lane.BaseSBOMSigners,
		ArtifactRefs:    artifactRefs,
		LaneID:          string(rc.lane.ID),
		LaneDigest:      rc.laneDigest.Wire(),
		CA:              rc.ca,
		UpstreamLook:    rc.upstreamLook,
		CAVolume:        rc.trust.ca,
		StepID:          stepID,
		StepPorts:       rc.stepPorts,
		NetworkRecords:  rc.networkRecords,
	}

	att, err := d.Execute(ctx, step, rc.laneState)
	if err != nil {
		return fmt.Errorf("%s: deploy failed: %w", safeName, err)
	}

	attJSON, err := att.JSON()
	if err != nil {
		return fmt.Errorf("%s: attestation marshal: %w", safeName, err)
	}
	log.Printf("OK     %s -> %s/%s", safeName, att.Sealed.LaneID, att.Sealed.Target.ID)

	outDir, err := os.MkdirTemp("", "strike-"+stepID+"-")
	if err != nil {
		return fmt.Errorf("%s: create temp dir: %w", safeName, err)
	}
	defer removeStrikeScratch(outDir)
	if writeErr := writeToOutputDir(outDir, "attestation.json", attJSON); writeErr != nil {
		return fmt.Errorf("%s: write attestation: %w", safeName, writeErr)
	}
	if att.Signed != nil {
		for _, w := range []struct {
			name string
			env  []byte
		}{
			{"slsa-provenance.sigstore.json", att.Signed.Sealed.Bundle},
			{"engine-context.sigstore.json", att.Signed.EngineContext.Bundle},
			{"informational.sigstore.json", att.Signed.Informational.Bundle},
		} {
			if writeErr := writeToOutputDir(outDir, w.name, w.env); writeErr != nil {
				return fmt.Errorf("%s: write %s: %w", safeName, w.name, writeErr)
			}
		}
	}
	return nil
}

func (rc *runContext) resolveImageDigest(ctx context.Context, step *lane.Step, safeName string) (lane.DigestRef, error) {
	if step.Pack != nil {
		digest, err := resolveDigest(ctx, rc.regClient, step.Pack.Base)
		if err != nil {
			return lane.DigestRef{}, fmt.Errorf("%s: pack base digest: %w", safeName, err)
		}
		return digest, nil
	}
	if edge, ok := rc.dag.ImageFromEdges[string(step.ID)]; ok {
		fromStep := string(edge.FromStep.ID)
		// The image output is id-less; it is registered and resolved by step via
		// the empty-output key, collision-free because a step that declares an
		// image output declares no other output (ADR-046).
		ref := lane.OutputRef{Step: spec.Identifier(fromStep), Output: ""}.Ref()
		handle, err := rc.laneState.Resolve(ref)
		if err != nil {
			return lane.DigestRef{}, fmt.Errorf("%s: imageFromStep %s: %w",
				safeName, ref, err)
		}
		digest, digestErr := lane.ManifestDigest(handle)
		if digestErr != nil {
			return lane.DigestRef{}, fmt.Errorf("%s: imageFromStep %s: %w",
				safeName, ref, digestErr)
		}
		// ADR-045: execute the producer's image by its content-addressed
		// digest, not the mutable WrapTag (ADR-046).
		rc.state.imageFromRefs[string(step.ID)] = handle.ImageRef()
		return digest, nil
	}
	digest, err := resolveDigest(ctx, rc.regClient, *step.Image)
	if err != nil {
		return lane.DigestRef{}, fmt.Errorf("%s: image digest: %w", safeName, err)
	}
	return digest, nil
}

func (rc *runContext) computeSpecHash(step *lane.Step, stepID string, imageDigest lane.DigestRef) (lane.DigestRef, string, error) {
	// Per ADR-027, an input is identified in the spec hash by the
	// canonical triple (from, mount, subpath); mount is unique per step
	// by disjointness, and subpath is "" when the whole producer output
	// is mounted. The hashed value remains the producer's spec hash.
	inputHashes := map[string]lane.DigestRef{}
	for _, e := range rc.dag.InputEdges[string(step.ID)] {
		from := lane.OutputRef{Step: e.FromStep.ID, Output: e.FromOutput.ID}.Ref()
		subpath := ""
		if e.Subpath != nil {
			subpath = string(*e.Subpath)
		}
		key := from + "|" + e.Mount.String() + "|" + subpath
		inputHashes[key] = rc.state.specHashes[string(e.FromStep.ID)]
	}

	key := registry.SpecHash(step, imageDigest, inputHashes, map[string]lane.DigestRef{})
	tag := registry.Tag(rc.lane.Registry, stepID, key)
	rc.state.specHashes[stepID] = key
	return key, tag, nil
}

func (rc *runContext) checkCache(ctx context.Context, step *lane.Step, stepID, safeName string, specHash lane.DigestRef) (bool, error) {
	if step.ForceRun {
		log.Printf("FORCED %s", safeName)
		return false, nil
	}

	tag := registry.WrapTag(string(rc.lane.ID), stepID, specHash)
	info, err := rc.engine.ImageInspect(ctx, tag)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, fmt.Errorf("cache check %s: %w", safeName, err)
	}

	sizeStr, ok := info.Annotations[registry.ContentSizeAnnotation]
	if !ok {
		log.Printf("CACHE-NO-SIZE %s (annotation missing)", safeName)
		return false, nil
	}
	size, sizeErr := strconv.ParseInt(sizeStr, 10, 64)
	badSize := sizeErr != nil || size <= 0
	if badSize {
		log.Printf("CACHE-BAD-SIZE %s (%q)", safeName, sizeStr)
		return false, nil
	}

	digest := lane.MustParseDigest(info.Digest)
	imageRef := registry.WrapDigestRef(string(rc.lane.ID), stepID, digest)
	if regErr := rc.registerCachedOutputs(ctx, step, stepID, safeName, imageRef); regErr != nil {
		return false, regErr
	}

	log.Printf("CACHED %s (%s)", safeName, tag)
	return true, nil
}

// registerCachedOutputs registers the digest-pinned handles for a cache hit.
// For file/directory outputs it recovers each output's LayerDiffID from the
// cached image: a cache hit means the outputs are byte-identical to a prior run
// (deterministic, ADR-046), and the producer assembles one layer per output in
// step.Outputs order (ADR-046 canonical ordering), so config rootfs.diff_ids[i]
// is output i's layer. The image output (step.Output) has no layer.
func (rc *runContext) registerCachedOutputs(ctx context.Context, step *lane.Step, stepID, safeName, imageRef string) error {
	if len(step.Outputs) > 0 {
		tarBytes, saveErr := registry.SaveImage(ctx, rc.engine, imageRef)
		if saveErr != nil {
			return fmt.Errorf("cache hit save %s: %w", safeName, saveErr)
		}
		diffIDs, diffErr := registry.LayerDiffIDs(tarBytes)
		if diffErr != nil {
			return fmt.Errorf("cache hit diff ids %s: %w", safeName, diffErr)
		}
		if len(diffIDs) != len(step.Outputs) {
			return fmt.Errorf("cache hit %s: image has %d layers, step declares %d outputs",
				safeName, len(diffIDs), len(step.Outputs))
		}
		for i, out := range step.Outputs {
			handle := lane.FileOutputHandle{
				Ref:         imageRef,
				OutputID:    out.ID,
				LayerDiffID: diffIDs[i],
			}
			if regErr := rc.laneState.Register(stepID, string(out.ID), handle); regErr != nil {
				return fmt.Errorf("cache hit register %s/%s: %w", stepID, out.ID, regErr)
			}
		}
	}
	if step.Output != "" {
		handle := lane.ImageOutputHandle{Ref: imageRef}
		if regErr := rc.laneState.Register(stepID, "", handle); regErr != nil {
			return fmt.Errorf("cache hit register %s image: %w", stepID, regErr)
		}
	}
	return nil
}

func (rc *runContext) executePack(ctx context.Context, step *lane.Step, stepID, safeName string) error {
	outDir, err := os.MkdirTemp("", "strike-"+stepID+"-")
	if err != nil {
		return fmt.Errorf("%s: create temp dir: %w", safeName, err)
	}
	defer removeStrikeScratch(outDir)

	inputPaths, err := rc.resolvePackInputPaths(ctx, step, outDir, safeName)
	if err != nil {
		return err
	}

	outRoot, err := os.OpenRoot(outDir)
	if err != nil {
		return fmt.Errorf("%s: open output dir: %w", safeName, err)
	}
	defer closer.Warn(outRoot, "step output root")

	if step.Output == "" {
		return fmt.Errorf("%s: pack output requires an image output", safeName)
	}
	outputID := stepID
	result, err := executor.Pack(executor.PackOpts{
		Spec:       step.Pack,
		InputPaths: inputPaths,
		OutputRoot: outRoot,
		OutputName: outputID,
	})
	if err != nil {
		return fmt.Errorf("%s: pack failed: %w", safeName, err)
	}

	// WrapImageOutputAsImage re-annotates the assembled image (reproducible
	// created stamp, content-size) before loading it, so the engine stores it
	// under a manifest digest distinct from result.Digest. The handle must
	// carry the engine-stored digest -- it is what a consumer (imageFromStep)
	// pulls by; result.Digest is the pre-annotation cross-validation anchor.
	specHash := rc.state.specHashes[stepID]
	tag := registry.WrapTag(string(rc.lane.ID), stepID, specHash)
	digest, _, wrapErr := rc.regClient.WrapImageOutputAsImage(ctx, outRoot, outputID, tag, nil)
	if wrapErr != nil {
		return fmt.Errorf("%s: wrap image: %w", safeName, wrapErr)
	}

	if result.Digest != digest {
		log.Printf("OK     %s -> %s (assembled %s)", safeName, digest, result.Digest)
	} else {
		log.Printf("OK     %s -> %s", safeName, digest)
	}

	handle := lane.ImageOutputHandle{
		Ref: registry.WrapDigestRef(string(rc.lane.ID), stepID, digest),
	}
	if regErr := rc.laneState.Register(stepID, "", handle); regErr != nil {
		return fmt.Errorf("%s: register artifact: %w", safeName, regErr)
	}
	return nil
}

func (rc *runContext) resolvePackInputPaths(ctx context.Context, step *lane.Step, scratchDir, safeName string) (map[string]string, error) {
	edges := rc.dag.PackFileEdges[string(step.ID)]
	inputPaths := make(map[string]string, len(edges))

	scratchRoot, rootErr := os.OpenRoot(scratchDir)
	if rootErr != nil {
		return nil, fmt.Errorf("%s: open scratch root: %w", safeName, rootErr)
	}
	defer closer.Warn(scratchRoot, "scratch root")
	if mkErr := scratchRoot.Mkdir("inputs", 0o750); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
		return nil, fmt.Errorf("%s: create inputs dir: %w", safeName, mkErr)
	}
	inputsRoot := filepath.Join(scratchDir, "inputs")

	for _, e := range edges {
		fromStep := string(e.FromStep.ID)
		fromOutput := e.FromOutput.ID

		handle, artErr := rc.laneState.Resolve(lane.OutputRef{Step: spec.Identifier(fromStep), Output: fromOutput}.Ref())
		if artErr != nil {
			return nil, fmt.Errorf("%s: pack input %s.%s: %w", safeName, fromStep, fromOutput, artErr)
		}
		fh, ok := handle.(lane.FileOutputHandle)
		if !ok {
			return nil, fmt.Errorf("%s: pack input %s.%s: not a file output", safeName, fromStep, fromOutput)
		}
		packDigest, digestErr := lane.ManifestDigest(fh)
		if digestErr != nil {
			return nil, fmt.Errorf("%s: pack input %s.%s digest: %w", safeName, fromStep, fromOutput, digestErr)
		}

		dedupDir := string(packDigest.Hex[:16]) + "-" + string(fh.OutputID)
		inputDir := filepath.Join(inputsRoot, dedupDir)
		if mkErr := scratchRoot.Mkdir(filepath.Join("inputs", dedupDir), 0o750); mkErr == nil {
			tarBytes, saveErr := registry.SaveImage(ctx, rc.engine, fh.Ref)
			if saveErr != nil {
				return nil, fmt.Errorf("%s: pack input %s save: %w", safeName, e.Dest, saveErr)
			}
			if extractErr := registry.ExtractLayer(tarBytes, fh.LayerDiffID, inputDir); extractErr != nil {
				return nil, fmt.Errorf("%s: pack input %s extract: %w", safeName, e.Dest, extractErr)
			}
		} else if !errors.Is(mkErr, os.ErrExist) {
			return nil, fmt.Errorf("%s: pack input mkdir: %w", safeName, mkErr)
		}

		inputPaths[e.Dest.String()] = filepath.Join(inputDir, lane.OutputContentPrefix(*e.FromOutput))
	}
	return inputPaths, nil
}

func (rc *runContext) executeContainerStep(ctx context.Context, step *lane.Step, stepID, safeName, tag string) error {
	secrets, err := lane.ResolveSecrets(step.Secrets, rc.lane.Secrets, rc.laneRoot)
	if err != nil {
		return fmt.Errorf("%s: secrets: %w", safeName, err)
	}

	inputSeeds, inputMounts, err := rc.buildInputDelivery(ctx, step)
	if err != nil {
		return fmt.Errorf("%s: inputs: %w", safeName, err)
	}

	volName, volErr := rc.createWorkdirVolume(ctx, step, safeName)
	if volErr != nil {
		return volErr
	}
	if volName != "" {
		defer func() {
			if rmErr := rc.engine.VolumeRemove(ctx, volName); rmErr != nil {
				log.Printf("WARN   %s: workdir volume remove: %v", safeName, rmErr)
			}
		}()
	}

	caps, ok := rc.capsules[stepID]
	if !ok {
		return fmt.Errorf("%s: no pre-built capsule", safeName)
	}
	defer func() {
		caps.CloseOutbound()
		rc.networkRecords[stepID] = caps.Records()
	}()

	run := executor.Run{
		Engine:       rc.engine,
		Step:         step,
		Seeds:        inputSeeds,
		ImageVolumes: inputMounts,
		VolumeName:   volName,
		Secrets:      secrets,
		ImageRef:     rc.state.imageFromRefs[stepID],
		Capsule:      caps,
		CAVolume:     rc.trust.ca,
		SSHVolume:    rc.trust.ssh[stepID],
	}
	containerID, execErr := run.Execute(ctx)
	if containerID != "" {
		defer func() {
			if rmErr := rc.engine.ContainerRemove(ctx, containerID); rmErr != nil {
				log.Printf("WARN   %s: container remove: %v", safeName, rmErr)
			}
		}()
	}
	if execErr != nil {
		return fmt.Errorf("%s: execution failed: %w", safeName, execErr)
	}

	if err := rc.wrapOutputs(ctx, step, stepID, safeName, containerID); err != nil {
		return err
	}
	if step.Provenance != nil {
		if err := rc.captureProvenance(ctx, step, safeName, containerID); err != nil {
			return fmt.Errorf("%s: provenance: %w", safeName, err)
		}
	}
	return rc.pushAndReport(ctx, step, safeName, tag)
}

func (rc *runContext) wrapOutputs(ctx context.Context, step *lane.Step, stepID, safeName, containerID string) error {
	if err := rc.wrapFileOutputs(ctx, step, stepID, safeName, containerID); err != nil {
		return err
	}
	if step.Output != "" {
		specHash := rc.state.specHashes[stepID]
		if wrapErr := rc.wrapImageOutput(ctx, step, stepID, safeName, containerID, specHash); wrapErr != nil {
			return wrapErr
		}
	}
	return nil
}

// wrapFileOutputs assembles every file and directory output of the held
// container into one canonical, digest-pinned step image (ADR-046) -- one
// annotated layer per output -- and registers a digest-pinned handle for each
// output. The manifest digest is the single integrity anchor; every consumer
// pulls the image by that digest and extracts the layer identified by the output id in
// its handle.
func (rc *runContext) wrapFileOutputs(ctx context.Context, step *lane.Step, stepID, safeName, containerID string) error {
	if len(step.Outputs) == 0 {
		return nil
	}
	workdir := step.Workdir.String()
	specHash := rc.state.specHashes[stepID]
	tag := registry.WrapTag(string(rc.lane.ID), stepID, specHash)

	outs := make([]registry.OutputArchive, 0, len(step.Outputs))
	for _, out := range step.Outputs {
		archivePath, stripPrefix, destPrefix := archiveReroot(workdir, out)
		stream, archErr := rc.engine.ContainerArchive(ctx, containerID, archivePath)
		if archErr != nil {
			return fmt.Errorf("%s: archive output %q: %w", safeName, out.ID, archErr)
		}
		defer closer.Warn(stream, "output archive stream")
		outs = append(outs, registry.OutputArchive{
			Tar:         stream,
			StripPrefix: stripPrefix,
			DestPrefix:  destPrefix,
			OutputID:    string(out.ID),
		})
	}

	result, wrapErr := rc.regClient.WrapOutputsAsImage(ctx, outs, tag)
	if wrapErr != nil {
		return fmt.Errorf("%s: assemble output image: %w", safeName, wrapErr)
	}

	imageRef := registry.WrapDigestRef(string(rc.lane.ID), stepID, result.Digest)
	for _, out := range step.Outputs {
		diffID, ok := result.LayerDiffIDs[string(out.ID)]
		if !ok {
			return fmt.Errorf("%s: output %q has no assembled layer", safeName, out.ID)
		}
		handle := lane.FileOutputHandle{
			Ref:         imageRef,
			OutputID:    out.ID,
			LayerDiffID: diffID,
		}
		if regErr := rc.laneState.Register(stepID, string(out.ID), handle); regErr != nil {
			return fmt.Errorf("%s: register output %q: %w", safeName, out.ID, regErr)
		}
	}
	return nil
}

// wrapImageOutput commits the held container to a new image, normalizes it
// through ggcr for reproducible digests (ADR-046), and registers the
// digest-pinned OutputHandle.
func (rc *runContext) wrapImageOutput(ctx context.Context, _ *lane.Step, stepID, safeName, containerID string, specHash lane.DigestRef) error {
	tag := registry.WrapTag(string(rc.lane.ID), stepID, specHash)

	imageID, commitErr := rc.engine.ContainerCommit(ctx, containerID)
	if commitErr != nil {
		return fmt.Errorf("%s: commit image output: %w", safeName, commitErr)
	}

	stream, saveErr := rc.engine.ImageSave(ctx, imageID)
	if saveErr != nil {
		return fmt.Errorf("%s: save committed image: %w", safeName, saveErr)
	}
	defer closer.Warn(stream, "committed image save stream")

	digest, _, err := rc.regClient.WrapImageArchiveAsImage(ctx, stream, tag)
	if err != nil {
		return fmt.Errorf("%s: normalize image output: %w", safeName, err)
	}

	handle := lane.ImageOutputHandle{
		Ref: registry.WrapDigestRef(string(rc.lane.ID), stepID, digest),
	}
	if regErr := rc.laneState.Register(stepID, "", handle); regErr != nil {
		return fmt.Errorf("%s: register output: %w", safeName, regErr)
	}
	return nil
}

func (rc *runContext) captureProvenance(ctx context.Context, step *lane.Step, safeName, containerID string) error {
	spec := step.Provenance
	if step.Workdir == nil {
		return fmt.Errorf("provenance declared without a workdir")
	}
	archivePath := path.Join(step.Workdir.String(), spec.Path.String())

	stream, err := rc.engine.ContainerArchive(ctx, containerID, archivePath)
	if err != nil {
		return fmt.Errorf("read provenance file %q: %w", spec.Path, err)
	}
	defer closer.Warn(stream, "provenance archive")

	fileReader, _, err := registry.FirstRegularFile(stream)
	if err != nil {
		return fmt.Errorf("read provenance file %q: %w", spec.Path, err)
	}
	raw, err := io.ReadAll(fileReader)
	if err != nil {
		return fmt.Errorf("read provenance file %q: %w", spec.Path, err)
	}
	rec, err := lane.ValidateProvenance(spec.Type, raw)
	if err != nil {
		return fmt.Errorf("validate %s provenance: %w", spec.Type, err)
	}
	log.Printf("PROV   %s type=%s", safeName, spec.Type)
	return rc.laneState.RecordProvenance(string(step.ID), rec)
}

// buildInputDelivery resolves each input edge to its delivery: inside the
// workdir, a seed written into the workdir volume before start; outside
// the workdir (including every input on a step with no workdir), a
// read-only image-volume mount referencing the producer image tag. It
// does not touch the host filesystem (ADR-036).
//
// Errors speak in lane terms ("input at <mount>"), never of the seed/mount
// mechanism. A single regular file cannot be mounted outside the workdir
// (the overlay is directory-granular); strike rejects it here, statically
// when the producing output is type file and at the validation walk when a
// subpath resolves to a regular file, rather than surfacing the engine's
// opaque runtime error.
func (rc *runContext) buildInputDelivery(ctx context.Context, step *lane.Step) ([]container.Seed, []container.ImageVolume, error) {
	edges := rc.dag.InputEdges[string(step.ID)]
	if len(edges) == 0 {
		return nil, nil, nil
	}

	var (
		seeds      []container.Seed
		mounts     []container.ImageVolume
		imageCache = make(map[string][]byte) // keyed by producer image ref (digest)
	)
	for _, e := range edges {
		ref := lane.OutputRef{Step: e.FromStep.ID, Output: e.FromOutput.ID}.Ref()
		art, artErr := rc.laneState.Resolve(ref)
		if artErr != nil {
			return nil, nil, fmt.Errorf("input at %q: source artifact %s not found: %w",
				e.Mount, ref, artErr)
		}
		fh, ok := art.(lane.FileOutputHandle)
		if !ok {
			return nil, nil, fmt.Errorf("input at %q: source artifact %s is not a file output", e.Mount, ref)
		}

		inside := false
		var rel string
		if step.Workdir != nil {
			rel, inside = relWithinWorkdir(step.Workdir.String(), e.Mount.String())
		}

		if inside {
			tarBytes, cacheErr := producerTar(ctx, rc.engine, imageCache, fh.Ref, e)
			if cacheErr != nil {
				return nil, nil, cacheErr
			}
			seedTar, buildErr := registry.SeedTarFromImage(tarBytes, fh.LayerDiffID, inputContentPath(e), rel)
			if buildErr != nil {
				return nil, nil, fmt.Errorf("input at %q: %w", e.Mount, buildErr)
			}
			seeds = append(seeds, container.Seed{
				Tar:  bytes.NewReader(seedTar),
				Path: step.Workdir.String(),
			})
			continue
		}

		// Outside the workdir (or no workdir): read-only image-volume mount.
		mount, mountErr := buildImageMount(ctx, rc.engine, imageCache, fh, e)
		if mountErr != nil {
			return nil, nil, mountErr
		}
		mounts = append(mounts, mount)
	}
	return seeds, mounts, nil
}

// buildImageMount validates and constructs a read-only image-volume mount for
// an input delivered outside the workdir. A single-file selection is rejected
// in lane terms, statically for a type:file output, by walk otherwise.
func buildImageMount(ctx context.Context, engine container.Engine, cache map[string][]byte, h lane.FileOutputHandle, e lane.InputEdge) (container.ImageVolume, error) {
	if e.FromOutput.Type == artifactTypeFile && e.Subpath == nil {
		return container.ImageVolume{}, singleFileOutsideErr(e)
	}
	tarBytes, cacheErr := producerTar(ctx, engine, cache, h.Ref, e)
	if cacheErr != nil {
		return container.ImageVolume{}, cacheErr
	}
	subPath := inputContentPath(e)
	kind, valErr := registry.ValidateImageMount(tarBytes, h.LayerDiffID, subPath)
	if valErr != nil {
		return container.ImageVolume{}, fmt.Errorf("input at %q: %w", e.Mount, valErr)
	}
	if kind == registry.MountKindFile {
		return container.ImageVolume{}, singleFileOutsideErr(e)
	}
	return container.ImageVolume{
		Source:      h.Ref,
		Destination: e.Mount.String(),
		SubPath:     subPath,
		ReadWrite:   false,
	}, nil
}

// producerTar returns the producer image's OCI-layout tar, exporting it
// from the engine at most once per ref across all input edges of a step.
func producerTar(ctx context.Context, engine container.Engine, cache map[string][]byte, ref string, e lane.InputEdge) ([]byte, error) {
	if tarBytes, ok := cache[ref]; ok {
		return tarBytes, nil
	}
	tarBytes, saveErr := registry.SaveImage(ctx, engine, ref)
	if saveErr != nil {
		return nil, fmt.Errorf("input at %q: save %s.%s: %w",
			e.Mount, e.FromStep.ID, e.FromOutput.ID, saveErr)
	}
	cache[ref] = tarBytes
	return tarBytes, nil
}

// singleFileOutsideErr is the lane-surface diagnostic for a single regular
// file selected as an input mounted outside the workdir. It names neither
// mount nor overlay; it tells the author what to change.
func singleFileOutsideErr(e lane.InputEdge) error {
	return fmt.Errorf("input at %q resolves to a single file, which can only "+
		"be delivered inside the step workdir; mount its parent directory, "+
		"use a directory output, or place it inside the workdir", e.Mount)
}

// archiveReroot returns the path to archive from the container and the
// (stripPrefix, destPrefix) for re-rooting that archive stream into the
// output's OCI layer.
//
// Podman's ContainerArchive roots its entries differently for a subdirectory
// than for a volume mountpoint (probe-confirmed, podman 5.4.2, stopped
// container with content written into the volume):
//
//   - a SUBDIRECTORY /out/tree -> entries prefixed with the subdir basename,
//     no leading slash: "tree/...". A single file /out/f -> the bare entry
//     "f".
//   - the WORKDIR MOUNTPOINT /out -> entries rooted at the volume root WITH a
//     leading slash: "/", "/node_modules", "/package.json". NOT prefixed with
//     the mountpoint basename.
//
// The layer must end rooted at OutputContentPrefix so the consumer
// (buildInputDelivery) and pack (resolvePackInputPaths) find content at
// <OutputContentPrefix>/... .
//
//   - path-bearing directory: strip the subdir basename podman prepended, then
//     re-root under OutputContentPrefix (basename == OutputContentPrefix, a no-op net
//     of strip+add).
//   - whole-workdir directory (no path): strip NOTHING. The mountpoint archive
//     already roots at the volume root; relUnderPrefix("") keeps each cleaned
//     name and path.Join(OutputContentPrefix, name) absorbs the leading slash, so
//     the whole workdir lands under the output name. Stripping the mountpoint
//     basename would match no entry (none carries it) and drop the layer.
//   - file: the archive is a single bare entry already named
//     basename(out.Path) == OutputContentPrefix; keep it (stripPrefix="",
//     destPrefix=""). Stripping its own name would drop the only entry.
//
// stripPrefix/destPrefix are unused for image outputs (wrapped via
// WrapImageArchiveAsImage); archivePath is used for all types.
func archiveReroot(workdir string, out lane.FileOutput) (archivePath, stripPrefix, destPrefix string) {
	archivePath = workdir
	if out.Path != nil {
		archivePath = path.Join(workdir, out.Path.String())
	}
	if out.Type == artifactTypeFile {
		return archivePath, "", ""
	}
	if out.Path == nil {
		return archivePath, "", lane.OutputContentPrefix(out)
	}
	return archivePath, path.Base(archivePath), lane.OutputContentPrefix(out)
}

// inputContentPath returns the in-image path within the producer's single
// content layer that the input selects: the optional subpath, offset by the
// output-type layer convention. Image outputs are rooted at the layer root;
// file/directory outputs sit under OutputContentPrefix. This is the caller-side
// re-rooting the engine boundary must not know about (Record 4).
func inputContentPath(e lane.InputEdge) string {
	base := ""
	if e.FromOutput.Type != artifactTypeImage {
		base = lane.OutputContentPrefix(*e.FromOutput)
	}
	if e.Subpath == nil {
		return base
	}
	return path.Join(base, string(*e.Subpath))
}

// relWithinWorkdir returns the path of mount relative to workdir, and whether
// mount is at or inside workdir. Lexical, component-wise: "/work" contains
// "/work" (".") and "/work/x", but not "/workspace".
func relWithinWorkdir(workdir, mount string) (string, bool) {
	w := path.Clean(workdir)
	m := path.Clean(mount)
	if m == w {
		return ".", true
	}
	if rest, ok := strings.CutPrefix(m, w+"/"); ok {
		return rest, true
	}
	return "", false
}

func (rc *runContext) pushAndReport(ctx context.Context, step *lane.Step, safeName, tag string) error {
	pushed := false
	if step.Output != "" {
		if err := rc.regClient.PushArtifact(ctx, tag); err != nil {
			return fmt.Errorf("%s: push failed: %w", safeName, err)
		}
		pushed = true
	}
	if pushed {
		log.Printf("OK     %s -> %s", safeName, tag)
	} else {
		log.Printf("OK     %s", safeName)
	}
	return nil
}

// createWorkdirVolume provisions an engine volume for the step's workdir.
// Returns ("", nil) when no workdir is set (pack steps, no outputs).
func (rc *runContext) createWorkdirVolume(ctx context.Context, step *lane.Step, safeName string) (string, error) {
	if step.Workdir == nil {
		return "", nil
	}
	volName := fmt.Sprintf("strike-wd-%s-%d", safeName, clock.Wall().UnixNano())
	if err := rc.engine.VolumeCreate(ctx, volName); err != nil {
		return "", fmt.Errorf("%s: create workdir volume: %w", safeName, err)
	}
	return volName, nil
}

// trustVolumes is the planned set of trust volumes for the lane: one CA
// volume (lane-wide) and one SSH volume per step with SSH peers (keyed
// by step name). All are created and seeded in one SeedVolumes batch
// before the step loop runs.
type trustVolumes struct {
	ssh map[string]string // step name -> ssh trust volume name; nil when no step needs SSH
	ca  string
}

// planTrustVolumes creates and populates the lane-wide CA trust volume
// plus one per-step SSH trust volume for every step with SSH peers. All
// volumes are filled in a single SeedVolumes batch (one throwaway helper
// container, N archive-PUTs) before the step loop runs. Returns the set
// of named volumes the orchestrator owns; the caller removes them at
// lane end.
func (rc *runContext) planTrustVolumes(ctx context.Context, caPEM []byte) (trustVolumes, error) {
	tv := trustVolumes{ssh: map[string]string{}}

	// CA (lane-wide).
	tv.ca = fmt.Sprintf("strike-ca-%s-%d", rc.lane.ID, clock.Wall().UnixNano())
	caTar, err := singleFileTar("ca-certificates.crt", caPEM, 0o644)
	if err != nil {
		return trustVolumes{}, fmt.Errorf("ca volume tar: %w", err)
	}
	seeds := []container.VolumeSeed{
		{Volume: tv.ca, Tar: bytes.NewReader(caTar)},
	}
	volumeNames := []string{tv.ca}

	// SSH (one per step with SSH peers). The capsule owns the per-peer
	// container ports and capability tokens; ssh_config is rendered by
	// capsule.SSHConfig().
	for i := range rc.lane.Steps {
		step := &rc.lane.Steps[i]
		caps := rc.capsules[string(step.ID)]
		kh, cfg := executor.SSHTrustContent(step.Peers, caps, rc.front.HostKeyPublic())
		if kh == nil {
			continue
		}
		name := fmt.Sprintf("strike-ssh-%s-%d", sanitizeForLog(string(step.ID)), clock.Wall().UnixNano())
		sshTar, tarErr := executor.SSHTrustTar(kh, cfg)
		if tarErr != nil {
			return trustVolumes{}, fmt.Errorf("ssh volume tar for %s: %w", step.ID, tarErr)
		}
		tv.ssh[string(step.ID)] = name
		seeds = append(seeds, container.VolumeSeed{
			Volume: name, Tar: bytes.NewReader(sshTar),
		})
		volumeNames = append(volumeNames, name)
	}

	// Create all volumes before seeding (SeedVolumes assumes they exist).
	for _, n := range volumeNames {
		if err := rc.engine.VolumeCreate(ctx, n); err != nil {
			rc.removeTrustVolumes(ctx, tv)
			return trustVolumes{}, fmt.Errorf("trust volume create %s: %w", n, err)
		}
	}

	// Seed them all in one batch.
	if err := rc.engine.SeedVolumes(ctx, seeds); err != nil {
		rc.removeTrustVolumes(ctx, tv)
		return trustVolumes{}, fmt.Errorf("trust volume seed: %w", err)
	}
	return tv, nil
}

// removeTrustVolumes best-effort removes every volume in tv. Errors are
// logged but not returned; cleanup is advisory.
func (rc *runContext) removeTrustVolumes(ctx context.Context, tv trustVolumes) {
	if tv.ca != "" {
		if err := rc.engine.VolumeRemove(ctx, tv.ca); err != nil {
			log.Printf("WARN   remove ca volume: %v", err)
		}
	}
	for stepID, n := range tv.ssh {
		if err := rc.engine.VolumeRemove(ctx, n); err != nil {
			log.Printf("WARN   remove ssh volume for %s: %v", stepID, err)
		}
	}
}

// singleFileTar builds a minimal tar archive containing one regular file.
func singleFileTar(name string, data []byte, mode int64) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     mode,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(data); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildCapsules constructs and starts a capsule for every run step (every
// step that is neither a deploy nor a pack step -- exactly the steps
// executeContainerStep runs), keyed by step name. Built during setup so the
// capsules exist before the front starts and before the dispatch map is built
// (ADR-038). Deploy and state-capture capsules are not built here;
// the deploy path owns them.
func (rc *runContext) buildCapsules(ctx context.Context) error {
	for i := range rc.lane.Steps {
		step := &rc.lane.Steps[i]
		if step.Deploy != nil || step.Pack != nil {
			continue
		}
		name := string(step.ID)
		caps, err := rc.startCapsule(ctx, name, sanitizeForLog(name), step.Peers)
		if err != nil {
			return err
		}
		rc.capsules[name] = caps
		for _, tok := range caps.Tokens() {
			if regErr := rc.front.Register(tok, caps); regErr != nil {
				return regErr
			}
		}
	}
	return nil
}

// stopCapsules stops every pre-built capsule at lane end. Per-step network
// records are snapshotted as each step finishes (executeContainerStep), so
// this only closes listeners; record collection is not repeated here.
func (rc *runContext) stopCapsules() {
	for name, caps := range rc.capsules {
		if stopErr := caps.Stop(); stopErr != nil {
			log.Printf("WARN   %s: capsule stop: %v", sanitizeForLog(name), stopErr)
		}
	}
}

// startCapsule constructs and starts a NetworkCapsule for one container
// unit, looked up by name in the pre-allocated host-port map. Every
// container unit gets a capsule: peer-less units get an empty allowlist
// (resolver denies every name, mediator denies every SNI), which
// replaces the former --network=none.
func (rc *runContext) startCapsule(ctx context.Context, name, safeName string, peers []lane.Peer) (*capsule.NetworkCapsule, error) {
	ports, ok := rc.stepPorts[name]
	if !ok {
		return nil, fmt.Errorf("%s: no pre-allocated host ports", safeName)
	}

	httpsPeers := httpsPeersOf(peers)
	peerTrusts := make([]mediator.PeerTrust, len(httpsPeers))
	for i, p := range httpsPeers {
		peerTrusts[i] = mediator.PeerTrust{Host: p.Host, Trust: p.Trust}
	}
	sshTargets := sshTargetsOf(peers)

	caps, capsErr := capsule.New(name, ports, peerTrusts, sshTargets, rc.front.Addr().Port(), rc.ca, rc.upstreamLook)
	if capsErr != nil {
		return nil, fmt.Errorf("%s: construct capsule: %w", safeName, capsErr)
	}
	if startErr := caps.Start(ctx); startErr != nil {
		return nil, fmt.Errorf("%s: start capsule: %w", safeName, startErr)
	}
	log.Printf("CAPSULE %s @ 127.0.0.1 r:%d m:%d (https=%d ssh=%d)", safeName, ports.Resolver, ports.Mediator, len(httpsPeers), len(sshTargets))
	return caps, nil
}

// httpsPeersOf returns the HTTPS peers from a step's peer list.
func httpsPeersOf(peers []lane.Peer) []lane.HTTPSPeer {
	var out []lane.HTTPSPeer
	for _, p := range peers {
		if h, ok := p.(lane.HTTPSPeer); ok {
			out = append(out, h)
		}
	}
	return out
}

// sshTargetsOf returns the SSH peers of a step as capsule SSH targets,
// in peer-list order.
func sshTargetsOf(peers []lane.Peer) []capsule.SSHTarget {
	var out []capsule.SSHTarget
	for _, p := range peers {
		if sp, ok := p.(lane.SSHPeer); ok {
			keys := make([]string, len(sp.KnownHosts))
			for j, e := range sp.KnownHosts {
				keys[j] = e.KeyType + " " + string(e.Key)
			}
			out = append(out, capsule.SSHTarget{Host: string(sp.Host), HostKeys: keys})
		}
	}
	return out
}
