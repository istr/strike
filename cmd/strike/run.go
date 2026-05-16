package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
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
	ctx       context.Context
	engine    container.Engine
	lane      *lane.Lane
	dag       *lane.DAG
	regClient *registry.Client
	engineID  *container.EngineIdentity
	state     *runState
	laneState *lane.State // artifact graph for deploy attestations
	laneRoot  *os.Root
	rekor     *executor.RekorClient // optional Rekor transparency log client
	laneDir   string
}

func (rc *runContext) runStep(stepName string) error {
	step := rc.dag.Steps[stepName]
	safeName := sanitizeForLog(stepName)

	timeout, err := lane.ParseDuration(step.Timeout, 10*clock.Minute)
	if err != nil {
		return fmt.Errorf("%s: invalid timeout %q: %w", safeName, *step.Timeout, err)
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
		Engine:       rc.engine,
		EngineID:     rc.engineID,
		Rekor:        rc.rekor,
		DAG:          rc.dag,
		ArtifactRefs: artifactRefs,
		SigningKey:   signingKey,
		KeyPassword:  keyPassword,
		LaneID:       rc.lane.LaneID,
	}

	att, err := d.Execute(ctx, step, rc.laneState)
	if err != nil {
		return fmt.Errorf("%s: deploy failed: %w", safeName, err)
	}

	attJSON, err := att.JSON()
	if err != nil {
		return fmt.Errorf("%s: attestation marshal: %w", safeName, err)
	}
	log.Printf("OK     %s -> %s/%s", safeName, att.LaneID, att.Target.ID)

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
		digest, err := resolveDigest(ctx, rc.regClient, string(step.Pack.Base))
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

		baseName := filepath.Base(e.FromOutput.Path.String())
		inputPaths[e.Dest.String()] = filepath.Join(inputDir, baseName)
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
	outDir, err := os.MkdirTemp("", "strike-"+stepName+"-")
	if err != nil {
		return fmt.Errorf("%s: create temp dir: %w", safeName, err)
	}
	defer removeStrikeScratch(outDir)

	secrets, err := lane.ResolveSecrets(step.Secrets, rc.lane.Secrets, rc.laneRoot)
	if err != nil {
		return fmt.Errorf("%s: secrets: %w", safeName, err)
	}

	inputMounts, err := rc.buildInputMounts(ctx, step, outDir)
	if err != nil {
		return fmt.Errorf("%s: input mounts: %w", safeName, err)
	}

	run := executor.Run{
		Engine:      rc.engine,
		Step:        step,
		InputMounts: inputMounts,
		OutputDir:   outDir,
		Secrets:     secrets,
		ImageRef:    rc.state.imageFromTags[stepName],
	}
	if execErr := run.Execute(ctx); execErr != nil {
		return fmt.Errorf("%s: execution failed: %w", safeName, execErr)
	}

	outRoot, rootErr := os.OpenRoot(outDir)
	if rootErr != nil {
		return fmt.Errorf("%s: open output root: %w", safeName, rootErr)
	}
	defer closer.Warn(outRoot, "container step output root")

	if err := rc.wrapOutputs(ctx, step, stepName, safeName, outRoot); err != nil {
		return err
	}
	if step.Provenance != nil {
		if err := rc.captureProvenance(step, safeName, outRoot); err != nil {
			return fmt.Errorf("%s: provenance: %w", safeName, err)
		}
	}
	return rc.pushAndReport(ctx, step, safeName, tag)
}

func (rc *runContext) wrapOutputs(ctx context.Context, step *lane.Step, stepName, safeName string, outRoot *os.Root) error {
	specHash := rc.state.specHashes[stepName]
	for _, out := range step.Outputs {
		tag := registry.WrapTag(rc.lane.LaneID, stepName, specHash)
		outName := filepath.Base(out.Path.String())
		var digest lane.Digest
		var size int64
		var err error
		switch out.Type {
		case "file":
			digest, size, err = rc.regClient.WrapFileAsImage(ctx, outRoot, outName, tag)
		case "directory":
			digest, size, err = rc.regClient.WrapDirectoryAsImage(ctx, outRoot, outName, tag)
		case artifactTypeImage:
			digest, size, err = rc.regClient.WrapImageOutputAsImage(ctx, outRoot, outName, tag)
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
	}
	return nil
}

// outputMountTarget is the fixed container path where the output directory is mounted.
const outputMountTarget = "/out"

func (rc *runContext) captureProvenance(step *lane.Step, safeName string, outRoot *os.Root) error {
	spec := step.Provenance
	// Map container path to relative path within the output root.
	// The output directory is mounted at /out, so /out/provenance.json -> provenance.json.
	rel, err := filepath.Rel(outputMountTarget, spec.Path.String())
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("provenance path %q is not within %s", spec.Path, outputMountTarget)
	}

	f, err := outRoot.Open(rel)
	if err != nil {
		return fmt.Errorf("read provenance file %q: %w", spec.Path, err)
	}
	raw, err := io.ReadAll(f)
	closer.Warn(f, "provenance file")
	if err != nil {
		return fmt.Errorf("read provenance file %q: %w", spec.Path, err)
	}
	rec, err := lane.ValidateProvenance(spec.Type, raw)
	if err != nil {
		return fmt.Errorf("validate %s provenance: %w", spec.Type, err)
	}
	if spec.RequireSigned != nil && *spec.RequireSigned && !rec.IsSigned() {
		return fmt.Errorf("provenance requires signature.verified=true, but record is unsigned")
	}
	log.Printf("PROV   %s type=%s signed=%v", safeName, spec.Type, rec.IsSigned())
	return rc.laneState.RecordProvenance(string(step.Name), rec)
}

func (rc *runContext) buildInputMounts(ctx context.Context, step *lane.Step, scratchDir string) ([]executor.Mount, error) {
	edges := rc.dag.InputEdges[string(step.Name)]
	if len(edges) == 0 {
		return nil, nil
	}

	scratchRoot, rootErr := os.OpenRoot(scratchDir)
	if rootErr != nil {
		return nil, fmt.Errorf("open scratch root: %w", rootErr)
	}
	defer closer.Warn(scratchRoot, "scratch root")
	if mkErr := scratchRoot.Mkdir("inputs", 0o750); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
		return nil, fmt.Errorf("create inputs dir: %w", mkErr)
	}
	inputsRoot := filepath.Join(scratchDir, "inputs")

	mounts := make([]executor.Mount, 0, len(edges))
	for _, e := range edges {
		srcPath, err := rc.resolveInputEdge(ctx, e, scratchRoot, inputsRoot)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, executor.Mount{
			Host:      srcPath,
			Container: e.Mount.String(),
			ReadOnly:  true,
		})
	}
	return mounts, nil
}

// resolveInputEdge extracts the producer output for a single input edge
// and returns the host path to bind-mount. It deduplicates extractions
// by digest prefix and validates subpath existence via *os.Root.
func (rc *runContext) resolveInputEdge(ctx context.Context, e lane.InputEdge, scratchRoot *os.Root, inputsRoot string) (string, error) {
	fromStep := string(e.FromStep.Name)
	ref := fromStep + "." + e.FromOutput.Name

	art, artErr := rc.laneState.Resolve(ref)
	if artErr != nil {
		return "", fmt.Errorf("input at %q: source artifact %s not found: %w",
			e.Mount, ref, artErr)
	}

	inputDir, err := rc.extractInputArtifact(ctx, e.Mount, ref, fromStep, art, scratchRoot, inputsRoot)
	if err != nil {
		return "", err
	}

	return resolveInputSubpath(e, inputDir)
}

// extractInputArtifact ensures the producer output is extracted exactly
// once (dedup by digest prefix) and returns the extraction directory.
func (rc *runContext) extractInputArtifact(ctx context.Context, mount lane.AbsPath, ref, fromStep string, art lane.Artifact, scratchRoot *os.Root, inputsRoot string) (string, error) {
	tag := registry.WrapTag(rc.lane.LaneID, fromStep, rc.state.specHashes[fromStep])

	// Dedup by digest prefix: hex-only chars, no traversal possible.
	dedupDir := art.Digest.Hex[:16]
	inputDir := filepath.Join(inputsRoot, dedupDir)
	if mkErr := scratchRoot.Mkdir(filepath.Join("inputs", dedupDir), 0o750); mkErr == nil {
		tarBytes, saveErr := registry.SaveImage(ctx, rc.engine, tag)
		if saveErr != nil {
			return "", fmt.Errorf("input at %q: save %s: %w", mount, ref, saveErr)
		}
		if extractErr := registry.ExtractSingleLayer(tarBytes, inputDir); extractErr != nil {
			return "", fmt.Errorf("input at %q: extract %s: %w", mount, ref, extractErr)
		}
	} else if !errors.Is(mkErr, os.ErrExist) {
		return "", fmt.Errorf("input at %q: mkdir: %w", mount, mkErr)
	}
	return inputDir, nil
}

// resolveInputSubpath resolves the content root within the extracted
// directory, applies an optional subpath, and verifies existence using
// *os.Root for path-confined I/O (CODE-STYLE.md#path-confined-io).
func resolveInputSubpath(e lane.InputEdge, inputDir string) (string, error) {
	ref := string(e.FromStep.Name) + "." + e.FromOutput.Name

	// Content root:
	//   - image output: rootfs root == inputDir
	//   - file/directory output: layer entry is at inputDir/<basename>
	contentRoot := inputDir
	if e.FromOutput.Type != artifactTypeImage {
		contentRoot = filepath.Join(inputDir, filepath.Base(e.FromOutput.Path.String()))
	}

	if e.Subpath == nil {
		return contentRoot, nil
	}

	// Stat via *os.Root so the subpath cannot escape contentRoot.
	root, err := os.OpenRoot(contentRoot)
	if err != nil {
		return "", fmt.Errorf("input at %q: open content root: %w", e.Mount, err)
	}
	defer closer.Warn(root, "input content root")

	if _, statErr := root.Stat(string(*e.Subpath)); statErr != nil {
		if os.IsNotExist(statErr) {
			return "", fmt.Errorf("input at %q: subpath %q not found in %s output",
				e.Mount, *e.Subpath, ref)
		}
		return "", fmt.Errorf("input at %q: stat subpath %q: %w", e.Mount, *e.Subpath, statErr)
	}

	return filepath.Join(contentRoot, string(*e.Subpath)), nil
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
