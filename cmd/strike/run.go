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
	"github.com/istr/strike/internal/transport"
)

// runState holds accumulated state across steps during a lane execution.
type runState struct {
	specHashes map[string]lane.Digest
	// imageFromTags maps a consumer step name to the producer's
	// local WrapTag, populated by resolveImageDigest when the
	// consumer has an image_from edge. Consumed by
	// executeContainerStep to override Step.Image in the executor
	// invocation without mutating the parsed Lane.
	imageFromTags map[string]string
}

func newRunState() *runState {
	return &runState{
		specHashes:    map[string]lane.Digest{},
		imageFromTags: map[string]string{},
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
	dag            *lane.DAG
	stepPorts      map[string]capsule.HostPorts       // mediated step name -> host ports
	networkRecords map[string]capsule.Records         // step name -> records
	capsules       map[string]*capsule.NetworkCapsule // run-step name -> pre-built capsule
	laneRoot       *os.Root
	rekor          *executor.RekorClient // optional Rekor transparency log client
	trust          trustVolumes
	laneDir        string
	resolverID     transport.ConnectionIdentity
}

func (rc *runContext) runStep(stepName string) error {
	step := rc.dag.Steps[stepName]
	safeName := sanitizeForLog(stepName)

	// Timeout resolution: explicit step value > lane-wide default > hard floor.
	var rawTimeout *lane.Duration
	switch {
	case step.Timeout != nil:
		rawTimeout = step.Timeout
	case rc.lane.Defaults != nil:
		d := lane.Duration(rc.lane.Defaults.Timeout)
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
		return rc.executeDeploy(ctx, step, stepName, safeName)
	}

	imageDigest, err := rc.resolveImageDigest(ctx, step, safeName)
	if err != nil {
		return err
	}
	specHash, tag, err := rc.computeSpecHash(step, stepName, imageDigest)
	if err != nil {
		return err
	}

	cached, cacheErr := rc.checkCache(ctx, step, stepName, safeName, specHash)
	if cacheErr != nil {
		return cacheErr
	}
	if cached {
		return nil
	}
	if err := rc.guardUnsignedImages(step, safeName); err != nil {
		return err
	}

	log.Printf("RUN    %s", safeName)

	if step.Pack != nil {
		return rc.executePack(ctx, step, stepName, safeName)
	}
	return rc.executeContainerStep(ctx, step, stepName, safeName, tag)
}

func (rc *runContext) executeDeploy(ctx context.Context, step *lane.Step, stepName, safeName string) error {
	log.Printf("DEPLOY %s", safeName)

	signingKey, keyPassword, err := rc.resolveDeploySecrets(step, safeName)
	if err != nil {
		return err
	}

	artifactRefs := make(map[string]string)
	for _, e := range rc.dag.DeployEdges[stepName] {
		artifactRefs[e.ArtifactName] = string(e.FromStep.Name) + "." + e.FromOutput.Name
	}

	d := &deploy.Deployer{
		Engine:         rc.engine,
		EngineID:       rc.engineID,
		ResolverID:     &rc.resolverID,
		Rekor:          rc.rekor,
		DAG:            rc.dag,
		ArtifactRefs:   artifactRefs,
		SigningKey:     signingKey,
		KeyPassword:    keyPassword,
		LaneID:         rc.lane.LaneID,
		CA:             rc.ca,
		UpstreamLook:   rc.upstreamLook,
		CAVolume:       rc.trust.ca,
		StepName:       stepName,
		StepPorts:      rc.stepPorts,
		NetworkRecords: rc.networkRecords,
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

	outDir, err := os.MkdirTemp("", "strike-"+stepName+"-")
	if err != nil {
		return fmt.Errorf("%s: create temp dir: %w", safeName, err)
	}
	defer removeStrikeScratch(outDir)
	if writeErr := writeToOutputDir(outDir, "attestation.json", attJSON); writeErr != nil {
		return fmt.Errorf("%s: write attestation: %w", safeName, writeErr)
	}
	if att.SignedEnvelope != nil {
		if writeErr := writeToOutputDir(outDir, "attestation.dsse.json", att.SignedEnvelope); writeErr != nil {
			return fmt.Errorf("%s: write signed attestation: %w", safeName, writeErr)
		}
	}
	return nil
}

func (rc *runContext) resolveImageDigest(ctx context.Context, step *lane.Step, safeName string) (lane.Digest, error) {
	if step.Pack != nil {
		digest, err := resolveDigest(ctx, rc.regClient, step.Pack.Base)
		if err != nil {
			return lane.Digest{}, fmt.Errorf("%s: pack base digest: %w", safeName, err)
		}
		return digest, nil
	}
	if edge, ok := rc.dag.ImageFromEdges[string(step.Name)]; ok {
		fromStep := string(edge.FromStep.Name)
		ref := fromStep + "." + edge.FromOutput.Name
		art, err := rc.laneState.Resolve(ref)
		if err != nil {
			return lane.Digest{}, fmt.Errorf("%s: image_from %s: %w",
				safeName, ref, err)
		}
		fromSpecHash, hashOK := rc.state.specHashes[fromStep]
		if !hashOK {
			return lane.Digest{}, fmt.Errorf("%s: image_from %s: producer spec hash not recorded",
				safeName, ref)
		}
		rc.state.imageFromTags[string(step.Name)] = registry.WrapTag(
			rc.lane.LaneID, fromStep, fromSpecHash)
		return art.Digest, nil
	}
	digest, err := resolveDigest(ctx, rc.regClient, *step.Image)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("%s: image digest: %w", safeName, err)
	}
	return digest, nil
}

func (rc *runContext) computeSpecHash(step *lane.Step, stepName string, imageDigest lane.Digest) (lane.Digest, string, error) {
	// Per ADR-027, an input is identified in the spec hash by the
	// canonical triple (from, mount, subpath); mount is unique per step
	// by disjointness, and subpath is "" when the whole producer output
	// is mounted. The hashed value remains the producer's spec hash.
	inputHashes := map[string]lane.Digest{}
	for _, e := range rc.dag.InputEdges[string(step.Name)] {
		from := string(e.FromStep.Name) + "." + e.FromOutput.Name
		subpath := ""
		if e.Subpath != nil {
			subpath = string(*e.Subpath)
		}
		key := from + "|" + e.Mount.String() + "|" + subpath
		inputHashes[key] = rc.state.specHashes[string(e.FromStep.Name)]
	}

	key := registry.SpecHash(step, imageDigest, inputHashes, map[string]lane.Digest{})
	tag := registry.Tag(rc.lane.Registry, stepName, key)
	rc.state.specHashes[stepName] = key
	return key, tag, nil
}

func (rc *runContext) checkCache(ctx context.Context, step *lane.Step, stepName, safeName string, specHash lane.Digest) (bool, error) {
	if step.ForceRun {
		log.Printf("FORCED %s", safeName)
		return false, nil
	}

	tag := registry.WrapTag(rc.lane.LaneID, stepName, specHash)
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

	signed := info.Annotations[registry.SignedAnnotation] == "true"
	digest := lane.MustParseDigest(info.Digest)
	for _, out := range step.Outputs {
		if regErr := rc.laneState.Register(stepName, out.Name, lane.Artifact{
			Type:   lane.ArtifactType(out.Type),
			Digest: digest,
			Size:   size,
			Signed: signed,
		}); regErr != nil {
			return false, fmt.Errorf("cache hit register %s/%s: %w", stepName, out.Name, regErr)
		}
	}

	log.Printf("CACHED %s (%s)", safeName, tag)
	return true, nil
}

func (rc *runContext) guardUnsignedImages(step *lane.Step, safeName string) error {
	if len(step.Peers) == 0 {
		return nil
	}
	for _, e := range rc.dag.InputEdges[string(step.Name)] {
		if e.FromOutput.Type != artifactTypeImage {
			continue
		}
		ref := string(e.FromStep.Name) + "." + e.FromOutput.Name
		art, err := rc.laneState.Resolve(ref)
		if err != nil {
			return fmt.Errorf("%s: input at %q: %w", safeName, e.Mount, err)
		}
		if !art.Signed {
			return fmt.Errorf("%s: input at %q is unsigned OCI image from %s",
				safeName, e.Mount, ref)
		}
	}
	return nil
}

func (rc *runContext) executePack(ctx context.Context, step *lane.Step, stepName, safeName string) error {
	outDir, err := os.MkdirTemp("", "strike-"+stepName+"-")
	if err != nil {
		return fmt.Errorf("%s: create temp dir: %w", safeName, err)
	}
	defer removeStrikeScratch(outDir)

	inputPaths, err := rc.resolvePackInputPaths(ctx, step, outDir, safeName)
	if err != nil {
		return err
	}
	signingKey, keyPassword, err := rc.resolvePackSecrets(step, safeName)
	if err != nil {
		return err
	}

	outRoot, err := os.OpenRoot(outDir)
	if err != nil {
		return fmt.Errorf("%s: open output dir: %w", safeName, err)
	}
	defer closer.Warn(outRoot, "step output root")

	if step.Outputs[0].Path == nil {
		return fmt.Errorf("%s: pack output requires a path", safeName)
	}
	outputName := filepath.Base(step.Outputs[0].Path.String())
	result, err := executor.Pack(ctx, executor.PackOpts{
		Spec:        step.Pack,
		InputPaths:  inputPaths,
		OutputRoot:  outRoot,
		OutputName:  outputName,
		SigningKey:  signingKey,
		KeyPassword: keyPassword,
		Rekor:       rc.rekor,
	})
	if err != nil {
		return fmt.Errorf("%s: pack failed: %w", safeName, err)
	}

	signed := signingKey != nil
	if regErr := rc.laneState.Register(stepName, step.Outputs[0].Name, lane.Artifact{
		Type:   artifactTypeImage,
		Digest: result.Digest,
		Rekor:  result.Rekor,
		Signed: signed,
	}); regErr != nil {
		return fmt.Errorf("%s: register artifact: %w", safeName, regErr)
	}

	specHash := rc.state.specHashes[stepName]
	tag := registry.WrapTag(rc.lane.LaneID, stepName, specHash)
	var extra map[string]string
	if signed {
		extra = map[string]string{registry.SignedAnnotation: "true"}
	}
	if _, _, wrapErr := rc.regClient.WrapImageOutputAsImage(ctx, outRoot, outputName, tag, extra); wrapErr != nil {
		return fmt.Errorf("%s: wrap image: %w", safeName, wrapErr)
	}
	log.Printf("OK     %s -> %s", safeName, result.Digest)
	return nil
}

func (rc *runContext) resolvePackInputPaths(ctx context.Context, step *lane.Step, scratchDir, safeName string) (map[string]string, error) {
	edges := rc.dag.PackFileEdges[string(step.Name)]
	inputPaths := make(map[string]string, len(edges))

	scratchRoot, rootErr := os.OpenRoot(scratchDir)
	if rootErr != nil {
		return nil, fmt.Errorf("%s: open scratch root: %w", safeName, rootErr)
	}
	defer func() {
		if cerr := scratchRoot.Close(); cerr != nil {
			log.Printf("WARN close scratch root: %v", cerr)
		}
	}()
	if mkErr := scratchRoot.Mkdir("inputs", 0o750); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
		return nil, fmt.Errorf("%s: create inputs dir: %w", safeName, mkErr)
	}
	inputsRoot := filepath.Join(scratchDir, "inputs")

	for _, e := range edges {
		fromStep := string(e.FromStep.Name)
		fromOutput := e.FromOutput.Name

		art, artErr := rc.laneState.Resolve(fromStep + "." + fromOutput)
		if artErr != nil {
			return nil, fmt.Errorf("%s: pack input %s.%s: %w", safeName, fromStep, fromOutput, artErr)
		}

		tag := registry.WrapTag(rc.lane.LaneID, fromStep, rc.state.specHashes[fromStep])

		dedupDir := art.Digest.Hex[:16]
		inputDir := filepath.Join(inputsRoot, dedupDir)
		if mkErr := scratchRoot.Mkdir(filepath.Join("inputs", dedupDir), 0o750); mkErr == nil {
			tarBytes, saveErr := registry.SaveImage(ctx, rc.engine, tag)
			if saveErr != nil {
				return nil, fmt.Errorf("%s: pack input %s save: %w", safeName, e.Dest, saveErr)
			}
			if extractErr := registry.ExtractSingleLayer(tarBytes, inputDir); extractErr != nil {
				return nil, fmt.Errorf("%s: pack input %s extract: %w", safeName, e.Dest, extractErr)
			}
		} else if !errors.Is(mkErr, os.ErrExist) {
			return nil, fmt.Errorf("%s: pack input mkdir: %w", safeName, mkErr)
		}

		inputPaths[e.Dest.String()] = filepath.Join(inputDir, lane.OutputLayerName(*e.FromOutput))
	}
	return inputPaths, nil
}

func (rc *runContext) resolveDeploySecrets(step *lane.Step, safeName string) ([]byte, []byte, error) {
	return rc.resolveSigningSecrets(step, safeName)
}

func (rc *runContext) resolvePackSecrets(step *lane.Step, safeName string) ([]byte, []byte, error) {
	return rc.resolveSigningSecrets(step, safeName)
}

func (rc *runContext) resolveSigningSecrets(step *lane.Step, safeName string) ([]byte, []byte, error) {
	var signingKey, keyPassword []byte
	for _, ref := range step.Secrets {
		source, ok := rc.lane.Secrets[ref.Name]
		if !ok {
			return nil, nil, fmt.Errorf("%s: secret %q not defined", safeName, ref.Name)
		}
		val, err := lane.ReadSecret(source, rc.laneRoot)
		if ref.Name == "cosign_key" {
			if err != nil {
				return nil, nil, fmt.Errorf("%s: secret cosign_key: %w", safeName, err)
			}
			signingKey = []byte(val.Expose())
		}
		if ref.Name == "cosign_password" {
			if err != nil {
				return nil, nil, fmt.Errorf("%s: secret cosign_password: %w", safeName, err)
			}
			keyPassword = []byte(val.Expose())
		}
	}
	return signingKey, keyPassword, nil
}

func (rc *runContext) executeContainerStep(ctx context.Context, step *lane.Step, stepName, safeName, tag string) error {
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

	caps, ok := rc.capsules[stepName]
	if !ok {
		return fmt.Errorf("%s: no pre-built capsule", safeName)
	}
	defer func() {
		caps.CloseOutbound()
		rc.networkRecords[stepName] = caps.Records()
	}()

	run := executor.Run{
		Engine:       rc.engine,
		Step:         step,
		Seeds:        inputSeeds,
		ImageVolumes: inputMounts,
		VolumeName:   volName,
		Secrets:      secrets,
		ImageRef:     rc.state.imageFromTags[stepName],
		Capsule:      caps,
		CAVolume:     rc.trust.ca,
		SSHVolume:    rc.trust.ssh[stepName],
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

	if err := rc.wrapOutputs(ctx, step, stepName, safeName, containerID); err != nil {
		return err
	}
	if step.Provenance != nil {
		if err := rc.captureProvenance(ctx, step, safeName, containerID); err != nil {
			return fmt.Errorf("%s: provenance: %w", safeName, err)
		}
	}
	return rc.pushAndReport(ctx, step, safeName, tag)
}

func (rc *runContext) wrapOutputs(ctx context.Context, step *lane.Step, stepName, safeName, containerID string) error {
	specHash := rc.state.specHashes[stepName]
	for _, out := range step.Outputs {
		if wrapErr := rc.wrapArchivedOutput(ctx, step, stepName, safeName, containerID, out, specHash); wrapErr != nil {
			return wrapErr
		}
	}
	return nil
}

// wrapArchivedOutput archives one output from the held container, wraps it
// into a content-addressed image (a canonicalized layer for file/directory,
// a loaded image for the image type), and registers the artifact.
func (rc *runContext) wrapArchivedOutput(ctx context.Context, step *lane.Step, stepName, safeName, containerID string, out lane.OutputSpec, specHash lane.Digest) error {
	workdir := step.Workdir.String()
	tag := registry.WrapTag(rc.lane.LaneID, stepName, specHash)

	// Podman's ContainerArchive prefixes entries with the archived path's
	// basename (probe-confirmed, podman 5.4.2): /out -> "out/...", /out/tree
	// -> "tree/...", a single file -> the bare basename. archiveReroot strips
	// that prefix and re-roots under OutputLayerName (directory), or keeps the
	// single file entry as-is (file), so the layer is rooted at
	// <OutputLayerName> for both consumer and pack.
	archivePath, stripPrefix, destPrefix := archiveReroot(workdir, out)

	stream, archErr := rc.engine.ContainerArchive(ctx, containerID, archivePath)
	if archErr != nil {
		return fmt.Errorf("%s: archive output %q: %w", safeName, out.Name, archErr)
	}
	defer closer.Warn(stream, "output archive stream")

	var (
		digest lane.Digest
		size   int64
		err    error
	)
	switch out.Type {
	case artifactTypeFile, "directory":
		digest, size, err = rc.regClient.WrapArchiveAsImage(ctx, stream, stripPrefix, destPrefix, tag)
	case artifactTypeImage:
		digest, size, err = rc.regClient.WrapImageArchiveAsImage(ctx, stream, tag)
	default:
		return fmt.Errorf("%s: unknown output type %q", safeName, out.Type)
	}
	if err != nil {
		return fmt.Errorf("%s: wrap output %q: %w", safeName, out.Name, err)
	}

	if regErr := rc.laneState.Register(stepName, out.Name, lane.Artifact{
		Type:   lane.ArtifactType(out.Type),
		Digest: digest,
		Size:   size,
	}); regErr != nil {
		return fmt.Errorf("%s: register artifact: %w", safeName, regErr)
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
	return rc.laneState.RecordProvenance(string(step.Name), rec)
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
	edges := rc.dag.InputEdges[string(step.Name)]
	if len(edges) == 0 {
		return nil, nil, nil
	}

	var (
		seeds      []container.Seed
		mounts     []container.ImageVolume
		imageCache = make(map[string][]byte) // producer tag -> image tar, exported once
	)
	for _, e := range edges {
		ref := string(e.FromStep.Name) + "." + e.FromOutput.Name
		if _, artErr := rc.laneState.Resolve(ref); artErr != nil {
			return nil, nil, fmt.Errorf("input at %q: source artifact %s not found: %w",
				e.Mount, ref, artErr)
		}
		tag := registry.WrapTag(rc.lane.LaneID, string(e.FromStep.Name),
			rc.state.specHashes[string(e.FromStep.Name)])

		inside := false
		var rel string
		if step.Workdir != nil {
			rel, inside = relWithinWorkdir(step.Workdir.String(), e.Mount.String())
		}

		if inside {
			tarBytes, cacheErr := producerTar(ctx, rc.engine, imageCache, tag, e)
			if cacheErr != nil {
				return nil, nil, cacheErr
			}
			seedTar, buildErr := registry.SeedTarFromImage(tarBytes, inputContentPath(e), rel)
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
		mount, mountErr := buildImageMount(ctx, rc.engine, imageCache, tag, e)
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
func buildImageMount(ctx context.Context, engine container.Engine, cache map[string][]byte, tag string, e lane.InputEdge) (container.ImageVolume, error) {
	if e.FromOutput.Type == artifactTypeFile && e.Subpath == nil {
		return container.ImageVolume{}, singleFileOutsideErr(e)
	}
	tarBytes, cacheErr := producerTar(ctx, engine, cache, tag, e)
	if cacheErr != nil {
		return container.ImageVolume{}, cacheErr
	}
	subPath := inputContentPath(e)
	kind, valErr := registry.ValidateImageMount(tarBytes, subPath)
	if valErr != nil {
		return container.ImageVolume{}, fmt.Errorf("input at %q: %w", e.Mount, valErr)
	}
	if kind == registry.MountKindFile {
		return container.ImageVolume{}, singleFileOutsideErr(e)
	}
	return container.ImageVolume{
		Source:      tag,
		Destination: e.Mount.String(),
		SubPath:     subPath,
		ReadWrite:   false,
	}, nil
}

// producerTar returns the producer image's OCI-layout tar, exporting it
// from the engine at most once per tag across all input edges of a step.
func producerTar(ctx context.Context, engine container.Engine, cache map[string][]byte, tag string, e lane.InputEdge) ([]byte, error) {
	if tarBytes, ok := cache[tag]; ok {
		return tarBytes, nil
	}
	tarBytes, saveErr := registry.SaveImage(ctx, engine, tag)
	if saveErr != nil {
		return nil, fmt.Errorf("input at %q: save %s.%s: %w",
			e.Mount, e.FromStep.Name, e.FromOutput.Name, saveErr)
	}
	cache[tag] = tarBytes
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
// Podman's ContainerArchive prefixes every entry with the basename of the
// archived path (probe-confirmed, podman 5.4.2): /out -> "out/...",
// /out/tree -> "tree/...", and a single file /out/f -> the bare entry "f".
// The layer must end rooted at OutputLayerName so the consumer
// (buildInputDelivery) and pack (resolvePackInputPaths) find content at
// <OutputLayerName>/... .
//
//   - directory: strip the basename podman prepended, then re-root under
//     OutputLayerName. For a path-bearing output basename == OutputLayerName
//     (a no-op net of strip+add); for a whole-workdir output they differ --
//     strip the workdir basename, add the output name.
//   - file: the archive is a single bare entry already named
//     basename(out.Path) == OutputLayerName; keep it (stripPrefix="",
//     destPrefix=""). Stripping its own name would drop the only entry.
//
// stripPrefix/destPrefix are unused for image outputs (wrapped via
// WrapImageArchiveAsImage); archivePath is used for all types.
func archiveReroot(workdir string, out lane.OutputSpec) (archivePath, stripPrefix, destPrefix string) {
	archivePath = workdir
	if out.Path != nil {
		archivePath = path.Join(workdir, out.Path.String())
	}
	if out.Type == artifactTypeFile {
		return archivePath, "", ""
	}
	return archivePath, path.Base(archivePath), lane.OutputLayerName(out)
}

// inputContentPath returns the in-image path within the producer's single
// content layer that the input selects: the optional subpath, offset by the
// output-type layer convention. Image outputs are rooted at the layer root;
// file/directory outputs sit under OutputLayerName. This is the caller-side
// re-rooting the engine boundary must not know about (Record 4).
func inputContentPath(e lane.InputEdge) string {
	base := ""
	if e.FromOutput.Type != artifactTypeImage {
		base = lane.OutputLayerName(*e.FromOutput)
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
	for _, out := range step.Outputs {
		if out.Type == artifactTypeImage {
			if err := rc.regClient.PushArtifact(ctx, tag); err != nil {
				return fmt.Errorf("%s: push failed: %w", safeName, err)
			}
			pushed = true
			break
		}
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
	tv.ca = fmt.Sprintf("strike-ca-%s-%d", rc.lane.LaneID, clock.Wall().UnixNano())
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
		caps := rc.capsules[string(step.Name)]
		kh, cfg := executor.SSHTrustContent(step.Peers, caps, rc.front.HostKeyPublic())
		if kh == nil {
			continue
		}
		name := fmt.Sprintf("strike-ssh-%s-%d", sanitizeForLog(string(step.Name)), clock.Wall().UnixNano())
		sshTar, tarErr := executor.SSHTrustTar(kh, cfg)
		if tarErr != nil {
			return trustVolumes{}, fmt.Errorf("ssh volume tar for %s: %w", step.Name, tarErr)
		}
		tv.ssh[string(step.Name)] = name
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
	for stepName, n := range tv.ssh {
		if err := rc.engine.VolumeRemove(ctx, n); err != nil {
			log.Printf("WARN   remove ssh volume for %s: %v", stepName, err)
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
// (ADR-038 roadmap). Deploy and state-capture capsules are not built here;
// the deploy path owns them.
func (rc *runContext) buildCapsules(ctx context.Context) error {
	for i := range rc.lane.Steps {
		step := &rc.lane.Steps[i]
		if step.Deploy != nil || step.Pack != nil {
			continue
		}
		name := string(step.Name)
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
				keys[j] = e.KeyType + " " + e.Key
			}
			out = append(out, capsule.SSHTarget{Host: string(sp.Host), HostKeys: keys})
		}
	}
	return out
}
