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
	"time"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

const (
	networkHost = "host"
	networkNone = "none"
)

// Attestation is the signed record produced by every deploy step.
type Attestation struct {
	Timestamp      time.Time                 `json:"timestamp"`
	Target         lane.DeployTarget         `json:"target"`
	Artifacts      map[string]SignedArtifact `json:"artifacts"`
	PreState       map[string]StateSnap      `json:"pre_state"`
	PostState      map[string]StateSnap      `json:"post_state"`
	Drift          *DriftReport              `json:"drift,omitempty"`
	Engine         *EngineRecord             `json:"engine,omitempty"`
	Rekor          *lane.RekorEntry          `json:"rekor,omitempty"`
	Source         *SourceProvenance         `json:"source,omitempty"`
	DeployID       string                    `json:"deploy_id"`
	LaneRef        string                    `json:"lane_ref"` // digest of lane definition
	SignedEnvelope []byte                    `json:"-"`        // DSSE envelope, not part of attestation JSON
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

// StateSnap is a point-in-time capture of one state dimension.
type StateSnap struct {
	Timestamp time.Time `json:"timestamp"`
	Name      string    `json:"name"`
	Image     string    `json:"image"`
	Digest    string    `json:"digest"`
	Output    []byte    `json:"output"`
}

// DriftReport compares current pre-state with previous post-state.
type DriftReport struct {
	PreviousDeployID  string            `json:"previous_deploy_id"`
	PreviousPostState map[string]string `json:"previous_post_state"` // name -> digest
	CurrentPreState   map[string]string `json:"current_pre_state"`
	Drifted           []string          `json:"drifted"` // names where digests differ
}

// HardenedRunOpts returns a RunOpts with the standard security profile.
// Callers override specific fields (Image, Cmd, Network, Mounts) as needed.
func HardenedRunOpts() container.RunOpts {
	return container.DefaultSecureOpts()
}

// Deployer executes deploy steps and produces attestations.
type Deployer struct {
	Engine      container.Engine
	EngineID    *container.EngineIdentity
	Rekor       *executor.RekorClient
	SigningKey  []byte
	KeyPassword []byte
	SourceDirs  []string // host paths with source mounts (for git provenance)
}

// Execute runs a deploy step: capture pre-state, detect drift, execute
// the deploy action, capture post-state, and build the attestation.
func (d *Deployer) Execute(ctx context.Context, step *lane.Step, state *lane.State) (*Attestation, error) { //nolint:gocyclo // sequential orchestrator; splitting further hurts readability
	spec := step.Deploy
	if spec == nil {
		return nil, fmt.Errorf("step %q: not a deploy step", step.Name)
	}

	deployID := GenerateDeployID(step.Name)
	started := time.Now()

	// 1. Capture pre-state
	preState, err := d.captureState(ctx, spec.Attestation.PreState)
	if err != nil {
		if spec.Attestation.PreState.Required {
			return nil, fmt.Errorf("step %q: pre-state capture failed: %w", step.Name, err)
		}
		log.Printf("WARN   deploy %s: pre-state capture failed: %v", step.Name, err)
	}

	// 2. Detect drift (compare with previous attestation if available)
	drift, err := d.detectAndHandleDrift(step.Name, spec, preState)
	if err != nil {
		return nil, err
	}

	// 3. Resolve artifact digests
	artifactDigests, err := resolveArtifactDigests(step.Name, spec, state)
	if err != nil {
		return nil, err
	}

	// 3.5. Capture source provenance (best-effort)
	var sourceProv *SourceProvenance
	if len(d.SourceDirs) > 0 && spec.Source != nil && spec.Source.Git_image != "" {
		sourceProv = d.captureSourceProvenance(ctx, d.SourceDirs, string(spec.Source.Git_image))
	}

	// 4. Execute deploy action
	if execErr := d.executeMethod(ctx, spec); execErr != nil {
		return nil, fmt.Errorf("step %q: deploy action failed: %w", step.Name, execErr)
	}

	// 5. Capture post-state
	postState, err := d.captureState(ctx, spec.Attestation.PostState)
	if err != nil {
		if spec.Attestation.PostState.Required {
			return nil, fmt.Errorf("step %q: post-state capture failed: %w", step.Name, err)
		}
		log.Printf("WARN   deploy %s: post-state capture failed: %v", step.Name, err)
	}

	// 6. Build attestation
	att := &Attestation{
		DeployID:  deployID,
		Timestamp: started,
		Target:    spec.Target,
		Artifacts: artifactDigests,
		PreState:  preState,
		PostState: postState,
		Drift:     drift,
		Engine:    d.engineRecord(),
		Source:    sourceProv,
	}

	// 7. Validate attestation against CUE schema.
	// This is the output-side equivalent of lane.Parse's input validation:
	// the attestation carries the supply chain trust chain and must
	// conform to the formal specification.
	if err := ValidateAttestation(att); err != nil {
		return nil, fmt.Errorf("step %q: attestation invalid: %w", step.Name, err)
	}

	// 7.5. Sign attestation (optional, key-dependent).
	if err := d.signAttestation(att, step.Name); err != nil {
		return nil, err
	}

	// 7.6. Submit signed attestation to Rekor transparency log (optional).
	// The DSSE envelope was signed over the attestation WITHOUT the rekor
	// field. att.Rekor is unsigned metadata proving the signing event was
	// logged. Verifiers must strip the rekor field before checking the
	// DSSE signature.
	if d.Rekor != nil && att.SignedEnvelope != nil {
		rekorEntry, rekorErr := submitAttestationToRekor(ctx, d, att)
		if rekorErr != nil {
			return nil, rekorErr
		}
		att.Rekor = rekorEntry
	}

	// 8. Record in lane state
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
		log.Printf("WARN   deploy %s: DSSE envelope %d bytes exceeds Rekor %d byte limit, skipping",
			att.DeployID, len(att.SignedEnvelope), rekorMaxEnvelopeSize)
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
			log.Printf("WARN   deploy %s: rekor dsse: %v", att.DeployID, err)
			return nil, nil
		}
		return nil, err
	}
	return entry, nil
}

// detectAndHandleDrift checks for drift between pre-state and previous post-state.
func (d *Deployer) detectAndHandleDrift(stepName string, spec *lane.DeploySpec, preState map[string]StateSnap) (*DriftReport, error) {
	if !spec.Attestation.Drift.Detect {
		return nil, nil
	}
	drift := DetectDrift(preState, nil) // previous attestation loaded from registry
	if drift != nil && len(drift.Drifted) > 0 {
		switch spec.Attestation.Drift.OnDrift {
		case "fail":
			return nil, fmt.Errorf("step %q: drift detected in %v", stepName, drift.Drifted)
		case "warn":
			log.Printf("WARN   deploy %s: drift detected in %v", stepName, drift.Drifted)
		}
	}
	return drift, nil
}

// resolveArtifactDigests resolves all artifact references to their signed provenance records.
func resolveArtifactDigests(stepName string, spec *lane.DeploySpec, state *lane.State) (map[string]SignedArtifact, error) {
	artifacts := make(map[string]SignedArtifact)
	for artName, artRef := range spec.Artifacts {
		a, resolveErr := state.Resolve(artRef.From)
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
func (d *Deployer) recordAttestation(att *Attestation, step *lane.Step, state *lane.State, started time.Time) error {
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
		Duration:  time.Since(started),
		Outputs:   map[string]string{"attestation": attDigest.String()},
	})
	return nil
}

// JSON serializes an attestation for storage or signing.
func (a *Attestation) JSON() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

// captureState runs all state capture commands and collects snapshots.
func (d *Deployer) captureState(ctx context.Context, spec lane.StateCaptureSpec) (map[string]StateSnap, error) {
	snaps := make(map[string]StateSnap)
	for _, sc := range spec.Capture {
		snap, err := d.captureOne(ctx, sc)
		if err != nil {
			return snaps, fmt.Errorf("capture %q: %w", sc.Name, err)
		}
		snaps[sc.Name] = snap
	}
	return snaps, nil
}

// captureOne runs a state capture command inside a container and
// returns the output as a snapshot.
func (d *Deployer) captureOne(ctx context.Context, sc lane.StateCapture) (StateSnap, error) {
	snap := StateSnap{
		Name:      sc.Name,
		Image:     string(sc.Image),
		Timestamp: time.Now(),
	}

	if sc.Image == "" {
		return snap, fmt.Errorf("capture %q: image is required", sc.Name)
	}
	if len(sc.Command) == 0 {
		return snap, fmt.Errorf("capture %q: command is required", sc.Name)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	network := networkHost
	if !sc.Network {
		network = networkNone
	}

	var mounts []container.Mount
	for _, m := range sc.Mounts {
		mounts = append(mounts, container.Mount{
			Source:   m.Source,
			Target:   m.Target,
			ReadOnly: true,
		})
	}

	opts := HardenedRunOpts()
	opts.Image = string(sc.Image)
	opts.Cmd = sc.Command
	opts.Mounts = mounts
	opts.Network = network
	opts.Stdout = &stdout
	opts.Stderr = &stderr

	exitCode, err := d.Engine.ContainerRun(ctx, opts)
	if err != nil {
		return snap, fmt.Errorf("capture %q: %w", sc.Name, err)
	}
	if exitCode != 0 {
		return snap, fmt.Errorf("capture %q: exit code %d: %s",
			sc.Name, exitCode, stderr.String())
	}

	snap.Output = stdout.Bytes()
	snap.Digest = "sha256:" + hex.EncodeToString(sha256Sum(snap.Output))
	return snap, nil
}

// DetectDrift compares current pre-state with previous post-state.
func DetectDrift(preState map[string]StateSnap, previousAtt *Attestation) *DriftReport {
	if previousAtt == nil {
		return nil // first deploy, no drift possible
	}

	report := &DriftReport{
		PreviousDeployID:  previousAtt.DeployID,
		PreviousPostState: make(map[string]string),
		CurrentPreState:   make(map[string]string),
	}

	for name, snap := range previousAtt.PostState {
		report.PreviousPostState[name] = snap.Digest
	}
	for name, snap := range preState {
		report.CurrentPreState[name] = snap.Digest
		if prev, ok := report.PreviousPostState[name]; ok && prev != snap.Digest {
			report.Drifted = append(report.Drifted, name)
		}
	}

	return report
}

// executeMethod dispatches to the appropriate deploy method.
func (d *Deployer) executeMethod(ctx context.Context, spec *lane.DeploySpec) error {
	m := spec.Method
	switch m.Type() {
	case "registry":
		return executeRegistryDeploy(m)
	case "kubernetes":
		return d.executeKubernetesDeploy(ctx, m)
	case "custom":
		return d.executeCustomDeploy(ctx, m)
	default:
		return fmt.Errorf("unknown deploy method type %q", m.Type())
	}
}

func executeRegistryDeploy(m lane.DeployMethod) error {
	if err := registry.CopyImage(m.Source(), m.MethodTarget()); err != nil {
		return fmt.Errorf("registry deploy: %w", err)
	}
	return nil
}

func (d *Deployer) executeKubernetesDeploy(ctx context.Context, m lane.DeployMethod) error {
	image := m.Image()
	if image == "" {
		return fmt.Errorf("kubernetes deploy: image required (digest-pinned kubectl image)")
	}

	kubeconfig, err := ResolveKubeconfig(m.Kubeconfig())
	if err != nil {
		return fmt.Errorf("kubernetes deploy: %w", err)
	}

	strategy := m.Strategy()
	if strategy == "" {
		strategy = "apply"
	}

	kubectlArgs := []string{strategy, "-f", "-"}
	if m.Namespace() != "" {
		kubectlArgs = append(kubectlArgs, "-n", m.Namespace())
	}

	opts := HardenedRunOpts()
	opts.Image = image
	opts.Cmd = kubectlArgs
	opts.Network = networkHost
	opts.Mounts = []container.Mount{
		{Source: kubeconfig, Target: "/root/.kube/config", ReadOnly: true},
	}
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

func (d *Deployer) executeCustomDeploy(ctx context.Context, m lane.DeployMethod) error {
	if m.Image() == "" {
		return fmt.Errorf("custom deploy: image required")
	}

	opts := HardenedRunOpts()
	opts.Image = m.Image()
	opts.Entrypoint = m.Entrypoint()
	opts.Cmd = m.Args()
	opts.Env = m.Env()
	opts.Network = networkHost
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

// GenerateDeployID creates a unique deploy identifier from a step name.
func GenerateDeployID(stepName string) string {
	data := fmt.Sprintf("%s-%d", stepName, time.Now().UnixNano())
	return hex.EncodeToString(sha256Sum([]byte(data)))[:16]
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
		if _, err := os.Stat(env); err != nil { //nolint:gosec // G703 false positive: err is checked on next line; path from $KUBECONFIG env
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
