package lane

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Compile-time check: Artifact is now CUE-generated in cue_types_lane_gen.go.
// If this line fails, the generated file is missing the Artifact definition.
var _ Artifact

// State tracks artifacts and step results across lane execution.
// All artifact references use "step_name.output_name" keys.
type State struct {
	Artifacts map[string]Artifact   `json:"artifacts"`
	Steps     map[string]StepResult `json:"steps"`
	mu        sync.RWMutex
}

// StepResult records execution metadata for a completed step.
type StepResult struct {
	StartedAt time.Time         `json:"started_at"`
	Inputs    map[string]string `json:"inputs"`
	Outputs   map[string]string `json:"outputs"`
	Name      string            `json:"name"`
	StepType  string            `json:"step_type"`
	Duration  time.Duration     `json:"duration"`
	ExitCode  int               `json:"exit_code"`
}

// NewState creates an empty lane state.
func NewState() *State {
	return &State{
		Artifacts: make(map[string]Artifact),
		Steps:     make(map[string]StepResult),
	}
}

// Register adds an artifact to the state under "step_name.output_name".
func (s *State) Register(stepName, outputName string, a Artifact) error {
	key := stepName + "." + outputName
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.Artifacts[key]; exists {
		return fmt.Errorf("artifact %q already registered", key)
	}
	if a.Digest == "" {
		return fmt.Errorf("artifact %q: digest is required", key)
	}
	s.Artifacts[key] = a
	return nil
}

// Resolve looks up an artifact by "step_name.output_name" reference.
func (s *State) Resolve(ref string) (Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.Artifacts[ref]
	if !ok {
		return Artifact{}, fmt.Errorf("artifact %q not found; available: %v", ref, s.artifactKeys())
	}
	return a, nil
}

// RecordStep stores the result of a completed step.
func (s *State) RecordStep(r StepResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Steps[r.Name] = r
}

// JSON serializes the state for debugging and attestation round-trips.
func (s *State) JSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.MarshalIndent(s, "", "  ")
}

func (s *State) artifactKeys() []string {
	keys := make([]string, 0, len(s.Artifacts))
	for k := range s.Artifacts {
		keys = append(keys, k)
	}
	return keys
}
