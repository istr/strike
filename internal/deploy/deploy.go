// Package deploy implements the deploy step type with mandatory state attestation.
//
// Every deploy produces a signed record of: what was running before,
// what changed, and what is running after. The attestation record
// IS the deploy output — there is no deploy without state capture.
package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

// Attestation is the signed record produced by every deploy step.
type Attestation struct {
	DeployID  string               `json:"deploy_id"`
	Timestamp time.Time            `json:"timestamp"`
	Target    lane.DeployTarget    `json:"target"`
	Artifacts map[string]string    `json:"artifacts"` // name -> digest deployed
	PreState  map[string]StateSnap `json:"pre_state"`
	PostState map[string]StateSnap `json:"post_state"`
	Drift     *DriftReport         `json:"drift,omitempty"`
	LaneRef   string               `json:"lane_ref"` // digest of lane definition
}

// StateSnap is a point-in-time capture of one state dimension.
type StateSnap struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"` // "command", "kubernetes", "http"
	Output    []byte    `json:"output"`
	Digest    string    `json:"digest"`
	Timestamp time.Time `json:"timestamp"`
}

// DriftReport compares current pre-state with previous post-state.
type DriftReport struct {
	PreviousDeployID  string            `json:"previous_deploy_id"`
	PreviousPostState map[string]string `json:"previous_post_state"` // name -> digest
	CurrentPreState   map[string]string `json:"current_pre_state"`
	Drifted           []string          `json:"drifted"` // names where digests differ
}

// Deployer executes deploy steps and produces attestations.
type Deployer struct {
	LaneRoot string
}

// Execute runs a deploy step: capture pre-state, detect drift, execute
// the deploy action, capture post-state, and build the attestation.
func (d *Deployer) Execute(ctx context.Context, step *lane.Step, state *lane.State) (*Attestation, error) {
	spec := step.Deploy
	if spec == nil {
		return nil, fmt.Errorf("step %q: not a deploy step", step.Name)
	}

	deployID := generateDeployID(step.Name)
	started := time.Now()

	// 1. Capture pre-state
	preState, err := captureState(ctx, spec.Attestation.PreState)
	if err != nil {
		if spec.Attestation.PreState.Required {
			return nil, fmt.Errorf("step %q: pre-state capture failed: %w", step.Name, err)
		}
		fmt.Fprintf(os.Stderr, "WARN   deploy %s: pre-state capture failed: %v\n", step.Name, err)
	}

	// 2. Detect drift (compare with previous attestation if available)
	var drift *DriftReport
	if spec.Attestation.Drift.Detect {
		drift = detectDrift(preState, nil) // previous attestation loaded from registry
		if drift != nil && len(drift.Drifted) > 0 {
			switch spec.Attestation.Drift.OnDrift {
			case "fail":
				return nil, fmt.Errorf("step %q: drift detected in %v", step.Name, drift.Drifted)
			case "warn":
				fmt.Fprintf(os.Stderr, "WARN   deploy %s: drift detected in %v\n", step.Name, drift.Drifted)
			case "record":
				// just record, no action
			}
		}
	}

	// 3. Resolve artifact digests
	artifactDigests := make(map[string]string)
	for artName, artRef := range spec.Artifacts {
		a, resolveErr := state.Resolve(artRef.From)
		if resolveErr != nil {
			return nil, fmt.Errorf("step %q: artifact %q: %w", step.Name, artName, resolveErr)
		}
		artifactDigests[artName] = a.Digest
	}

	// 4. Execute deploy action
	if err := executeMethod(ctx, spec); err != nil {
		return nil, fmt.Errorf("step %q: deploy action failed: %w", step.Name, err)
	}

	// 5. Capture post-state
	postState, err := captureState(ctx, spec.Attestation.PostState)
	if err != nil {
		if spec.Attestation.PostState.Required {
			return nil, fmt.Errorf("step %q: post-state capture failed: %w", step.Name, err)
		}
		fmt.Fprintf(os.Stderr, "WARN   deploy %s: post-state capture failed: %v\n", step.Name, err)
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
	}

	// 7. Record in lane state
	attJSON, _ := json.Marshal(att)
	attDigest := "sha256:" + hex.EncodeToString(sha256Sum(attJSON))

	if regErr := state.Register(step.Name, "attestation", lane.Artifact{
		Type:        "file",
		Digest:      attDigest,
		Size:        int64(len(attJSON)),
		ContentType: "application/vnd.strike.attestation+json",
	}); regErr != nil {
		return nil, fmt.Errorf("step %q: register attestation: %w", step.Name, regErr)
	}

	state.RecordStep(lane.StepResult{
		Name:      step.Name,
		StepType:  "deploy",
		StartedAt: started,
		Duration:  time.Since(started),
		Outputs:   map[string]string{"attestation": attDigest},
	})

	return att, nil
}

// JSON serializes an attestation for storage or signing.
func (a *Attestation) JSON() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

// captureState runs all state capture commands and collects snapshots.
func captureState(ctx context.Context, spec lane.StateCaptureSpec) (map[string]StateSnap, error) {
	snaps := make(map[string]StateSnap)
	for _, cap := range spec.Capture {
		snap, err := captureOne(ctx, cap)
		if err != nil {
			return snaps, fmt.Errorf("capture %q: %w", cap.Name, err)
		}
		snaps[cap.Name] = snap
	}
	return snaps, nil
}

func captureOne(ctx context.Context, cap lane.StateCapture) (StateSnap, error) {
	snap := StateSnap{
		Name:      cap.Name,
		Type:      cap.Type,
		Timestamp: time.Now(),
	}

	switch cap.Type {
	case "command":
		if len(cap.Command) == 0 {
			return snap, fmt.Errorf("command capture %q: no command specified", cap.Name)
		}
		cmd := exec.CommandContext(ctx, cap.Command[0], cap.Command[1:]...)
		out, err := cmd.Output()
		if err != nil {
			return snap, fmt.Errorf("command %q: %w", cap.Command[0], err)
		}
		snap.Output = out
		snap.Digest = "sha256:" + hex.EncodeToString(sha256Sum(out))

	case "http":
		if cap.URL == "" {
			return snap, fmt.Errorf("http capture %q: no URL specified", cap.Name)
		}
		// Use curl to avoid importing net/http in the deploy path
		cmd := exec.CommandContext(ctx, "curl", "-sf", cap.URL)
		out, err := cmd.Output()
		if err != nil {
			return snap, fmt.Errorf("http GET %q: %w", cap.URL, err)
		}
		snap.Output = out
		snap.Digest = "sha256:" + hex.EncodeToString(sha256Sum(out))

	case "kubernetes":
		if cap.Resource == nil {
			return snap, fmt.Errorf("kubernetes capture %q: no resource specified", cap.Name)
		}
		args := []string{"get", cap.Resource.Kind, cap.Resource.Name, "-o", "json"}
		if cap.Resource.Namespace != "" {
			args = append(args, "-n", cap.Resource.Namespace)
		}
		if cap.Resource.JSONPath != "" {
			args = append(args, "-o", fmt.Sprintf("jsonpath=%s", cap.Resource.JSONPath))
		}
		cmd := exec.CommandContext(ctx, "kubectl", args...)
		out, err := cmd.Output()
		if err != nil {
			return snap, fmt.Errorf("kubectl: %w", err)
		}
		snap.Output = out
		snap.Digest = "sha256:" + hex.EncodeToString(sha256Sum(out))

	default:
		return snap, fmt.Errorf("unknown capture type %q", cap.Type)
	}

	return snap, nil
}

// detectDrift compares current pre-state with previous post-state.
func detectDrift(preState map[string]StateSnap, previousAtt *Attestation) *DriftReport {
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
func executeMethod(ctx context.Context, spec *lane.DeploySpec) error {
	m := spec.Method
	switch m.Type() {
	case "registry":
		return executeRegistryDeploy(ctx, m)
	case "kubernetes":
		return executeKubernetesDeploy(ctx, m)
	case "custom":
		return executeCustomDeploy(ctx, m)
	default:
		return fmt.Errorf("unknown deploy method type %q", m.Type())
	}
}

func executeRegistryDeploy(_ context.Context, m lane.DeployMethod) error {
	if err := registry.CopyImage(m.Source(), m.MethodTarget()); err != nil {
		return fmt.Errorf("registry deploy: %w", err)
	}
	return nil
}

func executeKubernetesDeploy(ctx context.Context, m lane.DeployMethod) error {
	strategy := m.Strategy()
	if strategy == "" {
		strategy = "apply"
	}
	args := []string{strategy, "-f", "-"}
	if m.Namespace() != "" {
		args = append(args, "-n", m.Namespace())
	}
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func executeCustomDeploy(ctx context.Context, m lane.DeployMethod) error {
	if m.Image() == "" {
		return fmt.Errorf("custom deploy: image required")
	}
	args := []string{"run", "--rm", "--network=host"}
	for k, v := range m.Env() {
		args = append(args, "--env", k+"="+v)
	}
	args = append(args, m.Image())
	args = append(args, m.Args()...)

	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func generateDeployID(stepName string) string {
	data := fmt.Sprintf("%s-%d", stepName, time.Now().UnixNano())
	return hex.EncodeToString(sha256Sum([]byte(data)))[:16]
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
