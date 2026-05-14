// Package deploy implements the deploy step type with mandatory state attestation.
//
// Every deploy produces a signed record of: what was running before,
// what changed, and what is running after. The attestation record
// IS the deploy output -- there is no deploy without state capture.
package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/probe"
	"github.com/istr/strike/internal/registry"
)

// Attestation is the signed record produced by every deploy step.
type Attestation struct {
	Timestamp       clock.Time                `json:"timestamp"`
	Target          lane.DeployTarget         `json:"target"`
	Artifacts       map[string]SignedArtifact `json:"artifacts"`
	PreStateDigest  lane.Digest               `json:"pre_state_digest"`
	PostStateDigest lane.Digest               `json:"post_state_digest"`
	Engine          *EngineRecord             `json:"engine,omitempty"`
	Rekor           *lane.RekorEntry          `json:"rekor,omitempty"`
	Provenance      []lane.ProvenanceRecord   `json:"provenance"`
	Peers           map[string][]lane.Peer    `json:"peers"`
	LaneID          string                    `json:"lane_id"`
	LaneRef         string                    `json:"lane_ref"` // digest of lane definition
	SignedEnvelope  []byte                    `json:"-"`        // DSSE envelope, not part of attestation JSON
}

// SignedArtifact is the provenance record for one artifact.
type SignedArtifact struct {
	Signature *SignatureRecord `json:"signature,omitempty"`
	SBOM      *SBOMRecord      `json:"sbom,omitempty"`
	Rekor     *lane.RekorEntry `json:"rekor,omitempty"`
	Digest    string           `json:"digest"`
}

// SignatureRecord holds the signing metadata for an artifact.
type SignatureRecord struct {
	Annotations map[string]string `json:"annotations"`
	Algorithm   string            `json:"algorithm"`
	Payload     string            `json:"payload"`
}

// SBOMRecord holds SBOM metadata for an artifact.
type SBOMRecord struct {
	Format string `json:"format"`
	Digest string `json:"digest"`
}

// EngineRecord captures the engine's identity at deploy time.
// Verifiers use this to assess the trust level of the build environment.
type EngineRecord struct {
	// ConnectionType is "unix", "tls", or "mtls".
	ConnectionType string `json:"connection_type"`

	// CATrustMode is "pinned" (explicit CA) or "system" (OS trust store).
	// Empty for Unix socket connections.
	CATrustMode string `json:"ca_trust_mode,omitempty"`

	// ServerCertFingerprint is sha256:<hex> of the engine's certificate.
	// Empty for Unix socket connections.
	ServerCertFingerprint string `json:"server_cert_fingerprint,omitempty"`

	// ClientCertFingerprint is sha256:<hex> of the controller's certificate.
	// Empty unless mTLS is configured.
	ClientCertFingerprint string `json:"client_cert_fingerprint,omitempty"`

	// Rootless is true if the engine reported rootless mode.
	Rootless *bool `json:"rootless,omitempty"`

	// Version is the engine's self-reported version string.
	Version string `json:"version,omitempty"`
}

// HardenedRunOpts returns a RunOpts with the standard security profile.
// Callers override specific fields (Image, Cmd, Network, Mounts) as needed.
func HardenedRunOpts() container.RunOpts {
	return container.DefaultSecureOpts()
}

// Deployer executes deploy steps and produces attestations.
type Deployer struct {
	Engine       container.Engine
	ArtifactRefs map[string]string // pre-resolved: artifact name → "step.output" state ref
	EngineID     *container.EngineIdentity
	Rekor        *executor.RekorClient
	DAG          *lane.DAG
	LaneID       string
	SigningKey   []byte
	KeyPassword  []byte
}

// Execute runs a deploy step: capture pre-state, execute the deploy
// action, capture post-state, and build the attestation.
func (d *Deployer) Execute(ctx context.Context, step *lane.Step, state *lane.State) (*Attestation, error) {
	if step.Deploy == nil {
		return nil, fmt.Errorf("step %q: not a deploy step", step.Name)
	}
	spec := *step.Deploy
	started := clock.Wall()

	// 1. Capture pre-state -> canonical digest.
	preCaptures, err := d.captureState(ctx, spec.Attestation.PreState)
	if err != nil {
		if spec.Attestation.PreState.Required {
			return nil, fmt.Errorf("step %q: pre-state capture failed: %w", step.Name, err)
		}
		log.Printf("WARN   deploy %s: pre-state capture failed: %v", step.Name, err)
	}
	preDigest := StateDigest(preCaptures)

	// 2. Resolve artifact digests.
	artifactDigests, err := resolveArtifactDigests(step.Name, d.ArtifactRefs, state)
	if err != nil {
		return nil, err
	}

	// 3. Collect provenance records from transitive predecessors.
	provenance := state.CollectProvenance(d.DAG, string(step.Name))

	// 4. Execute deploy action.
	if execErr := d.executeMethod(ctx, spec, step.Peers); execErr != nil {
		return nil, fmt.Errorf("step %q: deploy action failed: %w", step.Name, execErr)
	}

	// 5. Capture post-state -> canonical digest.
	postCaptures, err := d.captureState(ctx, spec.Attestation.PostState)
	if err != nil {
		if spec.Attestation.PostState.Required {
			return nil, fmt.Errorf("step %q: post-state capture failed: %w", step.Name, err)
		}
		log.Printf("WARN   deploy %s: post-state capture failed: %v", step.Name, err)
	}
	postDigest := StateDigest(postCaptures)

	// 6. Build attestation.
	att := &Attestation{
		LaneID:          d.LaneID,
		Timestamp:       started,
		Target:          spec.Target,
		Artifacts:       artifactDigests,
		PreStateDigest:  preDigest,
		PostStateDigest: postDigest,
		Engine:          d.engineRecord(),
		Provenance:      provenance,
		Peers:           d.DAG.CollectPeers(string(step.Name)),
	}

	// 7. Validate attestation against CUE schema.
	if err := ValidateAttestation(att); err != nil {
		return nil, fmt.Errorf("step %q: attestation invalid: %w", step.Name, err)
	}

	// 8. Sign attestation (optional, key-dependent).
	if err := d.signAttestation(att, step.Name); err != nil {
		return nil, err
	}

	// 9. Submit signed attestation to Rekor transparency log (optional).
	if d.Rekor != nil && att.SignedEnvelope != nil {
		rekorEntry, rekorErr := submitAttestationToRekor(ctx, d, att)
		if rekorErr != nil {
			return nil, rekorErr
		}
		att.Rekor = rekorEntry
	}

	// 10. Record in lane state.
	if err := d.recordAttestation(att, step, state, started); err != nil {
		return nil, fmt.Errorf("step %q: %w", step.Name, err)
	}

	return att, nil
}

// signAttestation wraps the attestation in a signed DSSE envelope if a key is configured.
func (d *Deployer) signAttestation(att *Attestation, stepName string) error {
	if d.SigningKey == nil {
		log.Printf("WARN   deploy %s: attestation unsigned (no signing key configured)", stepName)
		return nil
	}
	attJSON, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("step %q: marshal attestation for signing: %w", stepName, err)
	}
	envelope, err := SignAttestation(attJSON, d.SigningKey, d.KeyPassword)
	if err != nil {
		return fmt.Errorf("step %q: sign attestation: %w", stepName, err)
	}
	att.SignedEnvelope = envelope
	return nil
}

const rekorMaxEnvelopeSize = 100 * 1024 // 100KB Rekor upload limit

// submitAttestationToRekor submits the signed DSSE envelope to Rekor.
// Returns nil entry on transient failure (fail open) or oversized envelope.
func submitAttestationToRekor(ctx context.Context, d *Deployer, att *Attestation) (*lane.RekorEntry, error) {
	if len(att.SignedEnvelope) > rekorMaxEnvelopeSize {
		log.Printf("WARN   deploy %s/%s: DSSE envelope %d bytes exceeds Rekor %d byte limit, skipping",
			att.LaneID, att.Target.ID, len(att.SignedEnvelope), rekorMaxEnvelopeSize)
		return nil, nil
	}

	pubPEM, err := executor.DerivePublicKeyPEM(d.SigningKey, d.KeyPassword)
	if err != nil {
		return nil, fmt.Errorf("rekor: derive public key: %w", err)
	}
	entry, err := d.Rekor.SubmitDSSE(ctx, att.SignedEnvelope, pubPEM)
	if err != nil {
		var w *executor.RekorTransientError
		if errors.As(err, &w) {
			log.Printf("WARN   deploy %s/%s: rekor dsse: %v", att.LaneID, att.Target.ID, err)
			return nil, nil
		}
		return nil, err
	}
	return entry, nil
}

// resolveArtifactDigests resolves all artifact references to their signed provenance records.
// refs maps artifact name → "step.output" state ref (pre-resolved by the caller from DAG edges).
func resolveArtifactDigests(stepName string, refs map[string]string, state *lane.State) (map[string]SignedArtifact, error) {
	artifacts := make(map[string]SignedArtifact)
	for artName, ref := range refs {
		a, resolveErr := state.Resolve(ref)
		if resolveErr != nil {
			return nil, fmt.Errorf("step %q: artifact %q: %w", stepName, artName, resolveErr)
		}
		artifacts[artName] = SignedArtifact{
			Digest: a.Digest.String(),
			Rekor:  a.Rekor,
		}
	}
	return artifacts, nil
}

// recordAttestation marshals and records the attestation in lane state.
func (d *Deployer) recordAttestation(att *Attestation, step *lane.Step, state *lane.State, started clock.Time) error {
	attJSON, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshal attestation: %w", err)
	}
	attHex := hex.EncodeToString(sha256Sum(attJSON))

	attDigest := lane.Digest{Algorithm: "sha256", Hex: attHex}
	if err := state.Register(step.Name, "attestation", lane.Artifact{
		Type:        "file",
		Digest:      attDigest,
		Size:        int64(len(attJSON)),
		ContentType: "application/vnd.strike.attestation+json",
	}); err != nil {
		return fmt.Errorf("register attestation: %w", err)
	}

	state.RecordStep(lane.StepResult{
		Name:      step.Name,
		StepType:  "deploy",
		StartedAt: started,
		Duration:  clock.Since(started),
		Outputs:   map[string]string{"attestation": attDigest.String()},
	})
	return nil
}

// JSON serializes an attestation for storage or signing.
func (a *Attestation) JSON() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

// captureState runs all state capture commands and returns the raw captures.
func (d *Deployer) captureState(ctx context.Context, spec lane.StateCaptureSpec) ([]captureSnap, error) {
	var captures []captureSnap
	for _, sc := range spec.Capture {
		snap, err := d.captureOne(ctx, sc)
		if err != nil {
			return captures, fmt.Errorf("capture %q: %w", sc.Name, err)
		}
		captures = append(captures, snap)
	}
	return captures, nil
}

// captureOne runs a state capture command inside a container.
func (d *Deployer) captureOne(ctx context.Context, sc lane.StateCapture) (captureSnap, error) {
	scratchDir, err := os.MkdirTemp("", "strike-ssh-capture-")
	if err != nil {
		return captureSnap{}, fmt.Errorf("ssh scratch: %w", err)
	}
	defer closer.Remove(scratchDir, "deploy scratch")

	if sc.Image == "" {
		return captureSnap{}, fmt.Errorf("capture %q: image is required", sc.Name)
	}
	if len(sc.Command) == 0 {
		return captureSnap{}, fmt.Errorf("capture %q: command is required", sc.Name)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	var mounts []container.Mount
	for _, m := range sc.Mounts {
		mounts = append(mounts, container.Mount{
			Source:   m.Source,
			Target:   m.Target.String(),
			ReadOnly: true,
		})
	}

	sshMount, sshEnv, err := executor.ConfigureSSHPeers(sc.Peers, scratchDir)
	if err != nil {
		return captureSnap{}, fmt.Errorf("ssh peer setup: %w", err)
	}
	if sshMount != nil {
		mounts = append(mounts, *sshMount)
	}

	agentMount, agentEnv, err := executor.StartAgentProxy(ctx, sc.Peers, scratchDir)
	if err != nil {
		return captureSnap{}, fmt.Errorf("ssh agent proxy setup: %w", err)
	}
	if agentMount != nil {
		mounts = append(mounts, *agentMount)
	}

	env := make(map[string]string, len(sshEnv)+len(agentEnv))
	for k, v := range sshEnv {
		env[k] = v
	}
	for k, v := range agentEnv {
		env[k] = v
	}

	opts := HardenedRunOpts()
	opts.Image = string(sc.Image)
	opts.Cmd = sc.Command
	opts.Mounts = mounts
	opts.Network = executor.NetworkMode(sc.Peers)
	opts.Env = env
	opts.Stdout = &stdout
	opts.Stderr = &stderr

	exitCode, err := d.Engine.ContainerRun(ctx, opts)
	if err != nil {
		return captureSnap{}, fmt.Errorf("capture %q: %w", sc.Name, err)
	}
	if exitCode != 0 {
		return captureSnap{}, fmt.Errorf("capture %q: exit code %d: %s",
			sc.Name, exitCode, stderr.String())
	}

	return captureSnap{
		name:   sc.Name,
		image:  string(sc.Image),
		output: stdout.Bytes(),
	}, nil
}

// executeMethod dispatches to the appropriate deploy method.
func (d *Deployer) executeMethod(ctx context.Context, spec lane.DeploySpec, peers []lane.Peer) error {
	switch m := spec.Method.(type) {
	case lane.DeployRegistry:
		return executeRegistryDeploy(m)
	case lane.DeployKubernetes:
		return d.executeKubernetesDeploy(ctx, m, peers)
	case lane.DeployCustom:
		return d.executeCustomDeploy(ctx, m, peers)
	default:
		return fmt.Errorf("unknown deploy method type %q", spec.Method.MethodType())
	}
}

func executeRegistryDeploy(m lane.DeployRegistry) error {
	if err := registry.CopyImage(m.Source, m.Target); err != nil {
		return fmt.Errorf("registry deploy: %w", err)
	}
	return nil
}

func (d *Deployer) executeKubernetesDeploy(ctx context.Context, m lane.DeployKubernetes, peers []lane.Peer) error {
	scratchDir, err := os.MkdirTemp("", "strike-ssh-k8s-")
	if err != nil {
		return fmt.Errorf("ssh scratch: %w", err)
	}
	defer closer.Remove(scratchDir, "deploy scratch")

	if m.Image == "" {
		return fmt.Errorf("kubernetes deploy: image required (digest-pinned kubectl image)")
	}

	kubeconfig, err := ResolveKubeconfig(m.Kubeconfig)
	if err != nil {
		return fmt.Errorf("kubernetes deploy: %w", err)
	}

	strategy := m.Strategy
	if strategy == "" {
		strategy = "apply"
	}

	kubectlArgs := []string{strategy, "-f", "-"}
	if m.Namespace != "" {
		kubectlArgs = append(kubectlArgs, "-n", m.Namespace)
	}

	mounts := []container.Mount{
		{Source: kubeconfig, Target: "/root/.kube/config", ReadOnly: true},
	}

	sshMount, sshEnv, err := executor.ConfigureSSHPeers(peers, scratchDir)
	if err != nil {
		return fmt.Errorf("ssh peer setup: %w", err)
	}
	if sshMount != nil {
		mounts = append(mounts, *sshMount)
	}

	agentMount, agentEnv, err := executor.StartAgentProxy(ctx, peers, scratchDir)
	if err != nil {
		return fmt.Errorf("ssh agent proxy setup: %w", err)
	}
	if agentMount != nil {
		mounts = append(mounts, *agentMount)
	}

	env := make(map[string]string, len(sshEnv)+len(agentEnv))
	for k, v := range sshEnv {
		env[k] = v
	}
	for k, v := range agentEnv {
		env[k] = v
	}

	opts := HardenedRunOpts()
	opts.Image = string(m.Image)
	opts.Cmd = kubectlArgs
	opts.Network = executor.NetworkMode(peers)
	opts.Mounts = mounts
	opts.Env = env
	opts.Stdin = os.Stdin
	opts.Stdout = os.Stdout
	opts.Stderr = os.Stderr

	exitCode, err := d.Engine.ContainerRun(ctx, opts)
	if err != nil {
		return fmt.Errorf("kubernetes deploy: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("kubernetes deploy: exit code %d", exitCode)
	}
	return nil
}

func (d *Deployer) executeCustomDeploy(ctx context.Context, m lane.DeployCustom, peers []lane.Peer) error {
	scratchDir, err := os.MkdirTemp("", "strike-ssh-custom-")
	if err != nil {
		return fmt.Errorf("ssh scratch: %w", err)
	}
	defer closer.Remove(scratchDir, "deploy scratch")

	if m.Image == "" {
		return fmt.Errorf("custom deploy: image required")
	}

	sshMount, sshEnv, err := executor.ConfigureSSHPeers(peers, scratchDir)
	if err != nil {
		return fmt.Errorf("ssh peer setup: %w", err)
	}

	agentMount, agentEnv, err := executor.StartAgentProxy(ctx, peers, scratchDir)
	if err != nil {
		return fmt.Errorf("ssh agent proxy setup: %w", err)
	}

	var mounts []container.Mount
	if sshMount != nil {
		mounts = append(mounts, *sshMount)
	}
	if agentMount != nil {
		mounts = append(mounts, *agentMount)
	}

	env := make(map[string]string, len(m.Env)+len(sshEnv)+len(agentEnv))
	for k, v := range m.Env {
		env[k] = v
	}
	for k, v := range sshEnv {
		env[k] = v
	}
	for k, v := range agentEnv {
		env[k] = v
	}

	opts := HardenedRunOpts()
	opts.Image = string(m.Image)
	opts.Entrypoint = m.Entrypoint
	opts.Cmd = m.Args
	opts.Env = env
	opts.Network = executor.NetworkMode(peers)
	opts.Mounts = mounts
	opts.Stdout = os.Stdout
	opts.Stderr = os.Stderr

	exitCode, err := d.Engine.ContainerRun(ctx, opts)
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return fmt.Errorf("custom deploy: exit code %d", exitCode)
	}
	return nil
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// ResolveKubeconfig returns the host path to the kubeconfig file.
// Priority: explicit override, $KUBECONFIG, default path.
func ResolveKubeconfig(override string) (string, error) {
	if override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("kubeconfig %q: %w", override, err)
		}
		return override, nil
	}
	if env := os.Getenv("KUBECONFIG"); env != "" {
		if _, err := probe.Stat(env); err != nil {
			return "", fmt.Errorf("$KUBECONFIG %q: %w", env, err)
		}
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	path := filepath.Join(home, ".kube", "config")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("default kubeconfig %q: %w", path, err)
	}
	return path, nil
}

func (d *Deployer) engineRecord() *EngineRecord {
	if d.EngineID == nil {
		return nil
	}
	rec := &EngineRecord{
		ConnectionType:        d.EngineID.Connection.Type,
		CATrustMode:           d.EngineID.Connection.CATrustMode,
		ServerCertFingerprint: d.EngineID.Connection.ServerCertFingerprint,
		ClientCertFingerprint: d.EngineID.Connection.ClientCertFingerprint,
	}
	if d.EngineID.Runtime != nil {
		rec.Rootless = &d.EngineID.Runtime.Rootless
		rec.Version = d.EngineID.Runtime.Version
	}
	return rec
}
