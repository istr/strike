package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

// runState holds accumulated state across steps during a lane execution.
type runState struct {
	specHashes map[string]lane.Digest
	outputDirs map[string]string
	ociDigests map[string]lane.Digest
	ociSigned  map[string]bool
}

func newRunState() *runState {
	return &runState{
		specHashes: map[string]lane.Digest{},
		outputDirs: map[string]string{},
		ociDigests: map[string]lane.Digest{},
		ociSigned:  map[string]bool{},
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
		return fmt.Errorf("%s: invalid timeout %q: %w", safeName, step.Timeout, err)
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

	if rc.checkCache(ctx, stepName, safeName, tag, specHash) {
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
	}

	att, err := d.Execute(ctx, step, rc.laneState)
	if err != nil {
		return fmt.Errorf("%s: deploy failed: %w", safeName, err)
	}

	attJSON, err := att.JSON()
	if err != nil {
		return fmt.Errorf("%s: attestation marshal: %w", safeName, err)
	}
	log.Printf("OK     %s -> deploy_id=%s", safeName, att.DeployID)

	outDir, err := os.MkdirTemp("", "strike-"+stepName+"-")
	if err != nil {
		return fmt.Errorf("%s: create temp dir: %w", safeName, err)
	}
	if writeErr := writeToOutputDir(outDir, "attestation.json", attJSON); writeErr != nil {
		return fmt.Errorf("%s: write attestation: %w", safeName, writeErr)
	}
	if att.SignedEnvelope != nil {
		if writeErr := writeToOutputDir(outDir, "attestation.dsse.json", att.SignedEnvelope); writeErr != nil {
			return fmt.Errorf("%s: write signed attestation: %w", safeName, writeErr)
		}
	}
	rc.state.outputDirs[stepName] = outDir
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
		key := string(edge.FromStep.Name) + "/" + edge.FromOutput.Name
		digest, ok := rc.state.ociDigests[key]
		if !ok {
			return lane.Digest{}, fmt.Errorf("%s: image_from %s/%s: digest not available",
				safeName, edge.FromStep.Name, edge.FromOutput.Name)
		}
		step.Image = "localhost/strike:" + digest.Hex[:12]
		return digest, nil
	}
	digest, err := resolveDigest(ctx, rc.regClient, step.Image)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("%s: image digest: %w", safeName, err)
	}
	return digest, nil
}

func (rc *runContext) computeSpecHash(step *lane.Step, stepName string, imageDigest lane.Digest) (lane.Digest, string, error) {
	inputHashes := map[string]lane.Digest{}
	for _, e := range rc.dag.InputEdges[string(step.Name)] {
		inputHashes[e.LocalName] = rc.state.specHashes[string(e.FromStep.Name)]
	}

	key := registry.SpecHash(step, imageDigest, inputHashes, map[string]lane.Digest{})
	tag := registry.Tag(rc.lane.Registry, stepName, key)
	rc.state.specHashes[stepName] = key
	return key, tag, nil
}

func (rc *runContext) checkCache(ctx context.Context, stepName, safeName, tag string, specHash lane.Digest) bool {
	if !registry.Lookup(ctx, rc.regClient, tag, specHash.String()) {
		return false
	}
	log.Printf("CACHED %s (%s)", safeName, tag)
	rc.state.outputDirs[stepName] = cachedOutputDir(tag)
	return true
}

func (rc *runContext) guardUnsignedImages(step *lane.Step, safeName string) error {
	if len(step.Peers) == 0 {
		return nil
	}
	for _, e := range rc.dag.InputEdges[string(step.Name)] {
		if e.FromOutput.Type != artifactTypeImage {
			continue
		}
		key := string(e.FromStep.Name) + "/" + e.FromOutput.Name
		if !rc.state.ociSigned[key] {
			return fmt.Errorf("%s: input %q is unsigned OCI image from %s.%s",
				safeName, e.LocalName, e.FromStep.Name, e.FromOutput.Name)
		}
	}
	return nil
}

func (rc *runContext) executePack(ctx context.Context, step *lane.Step, stepName, safeName string) error {
	inputPaths, err := rc.resolvePackInputPaths(step, safeName)
	if err != nil {
		return err
	}
	signingKey, keyPassword, err := rc.resolvePackSecrets(step, safeName)
	if err != nil {
		return err
	}

	outDir, err := os.MkdirTemp("", "strike-"+stepName+"-")
	if err != nil {
		return fmt.Errorf("%s: create temp dir: %w", safeName, err)
	}

	outRoot, err := os.OpenRoot(outDir)
	if err != nil {
		return fmt.Errorf("%s: open output dir: %w", safeName, err)
	}
	defer outRoot.Close() //nolint:errcheck // best-effort cleanup

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

	rc.state.outputDirs[stepName] = outDir
	outKey := stepName + "/" + step.Outputs[0].Name
	rc.state.ociDigests[outKey] = result.Digest
	rc.state.ociSigned[outKey] = signingKey != nil

	if regErr := rc.laneState.Register(stepName, step.Outputs[0].Name, lane.Artifact{
		Type:   artifactTypeImage,
		Digest: result.Digest,
		Rekor:  result.Rekor,
	}); regErr != nil {
		return fmt.Errorf("%s: register artifact: %w", safeName, regErr)
	}

	if err := rc.regClient.LoadOCITarByDigest(ctx, outRoot, outputName, result.Digest); err != nil {
		return fmt.Errorf("%s: load image: %w", safeName, err)
	}
	log.Printf("OK     %s -> %s", safeName, result.Digest)
	return nil
}

func (rc *runContext) resolvePackInputPaths(step *lane.Step, safeName string) (map[string]string, error) {
	edges := rc.dag.PackFileEdges[string(step.Name)]
	inputPaths := make(map[string]string, len(edges))
	for _, e := range edges {
		hostPath := filepath.Join(
			rc.state.outputDirs[string(e.FromStep.Name)],
			filepath.Base(e.FromOutput.Path.String()),
		)
		inputPaths[e.Dest.String()] = hostPath
	}
	_ = safeName // reserved for future error wrapping
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

	secrets, err := lane.ResolveSecrets(step.Secrets, rc.lane.Secrets, rc.laneRoot)
	if err != nil {
		return fmt.Errorf("%s: secrets: %w", safeName, err)
	}

	inputMounts := rc.buildInputMounts(step)

	run := executor.Run{
		Engine:      rc.engine,
		Step:        step,
		InputMounts: inputMounts,
		OutputDir:   outDir,
		Secrets:     secrets,
	}
	if execErr := run.Execute(ctx); execErr != nil {
		return fmt.Errorf("%s: execution failed: %w", safeName, execErr)
	}

	rc.state.outputDirs[stepName] = outDir

	outRoot, err := os.OpenRoot(outDir)
	if err != nil {
		return fmt.Errorf("%s: open output dir: %w", safeName, err)
	}
	defer outRoot.Close() //nolint:errcheck // best-effort cleanup

	if err := rc.registerFileOutputs(step, stepName, safeName, outDir, outRoot); err != nil {
		return err
	}
	if err := rc.loadOCIOutputs(ctx, step, stepName, safeName, outRoot); err != nil {
		return err
	}
	if step.Provenance != nil {
		if err := rc.captureProvenance(step, safeName, outDir); err != nil {
			return fmt.Errorf("%s: provenance: %w", safeName, err)
		}
	}
	return rc.pushAndReport(ctx, step, safeName, tag)
}

func (rc *runContext) registerFileOutputs(step *lane.Step, stepName, safeName, outDir string, outRoot *os.Root) error {
	for _, out := range step.Outputs {
		if out.Type == artifactTypeImage {
			continue
		}
		relName := filepath.Base(out.Path.String())
		outPath := filepath.Join(outDir, relName)
		if out.Expected != nil {
			info, statErr := os.Stat(outPath) //nolint:gosec // G703: outPath is outDir (our temp dir) + filepath.Base (no traversal)
			if statErr != nil {
				return fmt.Errorf("%s: output %q: %w", safeName, out.Name, statErr)
			}
			if valErr := executor.ValidateOutput(outPath, info, out.Expected); valErr != nil {
				return fmt.Errorf("%s: output %q validation: %w", safeName, out.Name, valErr)
			}
		}
		var h lane.Digest
		var size int64
		var hashErr error
		if out.Type == "directory" {
			h, size, hashErr = registry.HashDir(outRoot, outDir, relName)
		} else {
			h, hashErr = registry.HashFile(outRoot, relName)
		}
		if hashErr != nil {
			return fmt.Errorf("%s: hash output %q: %w", safeName, out.Name, hashErr)
		}
		if regErr := rc.laneState.Register(stepName, out.Name, lane.Artifact{
			Type:   lane.ArtifactType(out.Type),
			Digest: h,
			Size:   size,
		}); regErr != nil {
			return fmt.Errorf("%s: register artifact: %w", safeName, regErr)
		}
	}
	return nil
}

// outputMountTarget is the fixed container path where the output directory is mounted.
const outputMountTarget = "/out"

func (rc *runContext) captureProvenance(step *lane.Step, safeName, outDir string) error {
	spec := step.Provenance
	// Map container path to host path. The output directory is mounted at /out,
	// so /out/provenance.json → outDir/provenance.json.
	rel, err := filepath.Rel(outputMountTarget, spec.Path.String())
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("provenance path %q is not within %s", spec.Path, outputMountTarget)
	}
	hostPath := filepath.Join(outDir, rel)

	raw, err := os.ReadFile(hostPath) //nolint:gosec // G304: path is outDir (our temp) + validated relative
	if err != nil {
		return fmt.Errorf("read provenance file %q: %w", spec.Path, err)
	}
	rec, err := lane.ValidateProvenance(spec.Type, raw)
	if err != nil {
		return fmt.Errorf("validate %s provenance: %w", spec.Type, err)
	}
	if spec.RequireSigned && !rec.IsSigned() {
		return fmt.Errorf("provenance requires signature.verified=true, but record is unsigned")
	}
	log.Printf("PROV   %s type=%s signed=%v", safeName, spec.Type, rec.IsSigned())
	return rc.laneState.RecordProvenance(string(step.Name), rec)
}

func (rc *runContext) buildInputMounts(step *lane.Step) []executor.Mount {
	edges := rc.dag.InputEdges[string(step.Name)]
	mounts := make([]executor.Mount, len(edges))
	for i, e := range edges {
		mounts[i] = executor.Mount{
			Host:      filepath.Join(rc.state.outputDirs[string(e.FromStep.Name)], filepath.Base(e.FromOutput.Path.String())),
			Container: e.Mount.String(),
			ReadOnly:  true,
		}
	}
	return mounts
}

func (rc *runContext) loadOCIOutputs(ctx context.Context, step *lane.Step, stepName, safeName string, outRoot *os.Root) error {
	for _, out := range step.Outputs {
		if out.Type != artifactTypeImage {
			continue
		}
		relName := filepath.Base(out.Path.String())
		digest, err := rc.regClient.LoadOCITar(ctx, outRoot, relName)
		if err != nil {
			return fmt.Errorf("%s: oci-tar load %q: %w", safeName, out.Name, err)
		}
		key := stepName + "/" + out.Name
		rc.state.ociDigests[key] = digest

		if regErr := rc.laneState.Register(stepName, out.Name, lane.Artifact{
			Type:   lane.ArtifactType(out.Type),
			Digest: digest,
		}); regErr != nil {
			return fmt.Errorf("%s: register artifact: %w", safeName, regErr)
		}

		log.Printf("       %s/%s -> %s", safeName, out.Name, digest)
	}
	return nil
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
