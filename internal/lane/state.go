package lane

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/istr/strike/internal/clock"
)

// Compile-time check: Artifact is now CUE-generated in cue_types_lane_gen.go.
// If this line fails, the generated file is missing the Artifact definition.
var _ Artifact

// State tracks artifacts and step results across lane execution.
// All artifact references use "step_name.output_name" keys.
type State struct {
	Artifacts  map[string]Artifact         `json:"artifacts"`
	Steps      map[string]StepResult       `json:"steps"`
	Provenance map[string]ProvenanceRecord `json:"provenance"`
	mu         sync.RWMutex
}

// StepResult records execution metadata for a completed step.
type StepResult struct {
	StartedAt clock.Time        `json:"started_at"`
	Inputs    map[string]string `json:"inputs"`
	Outputs   map[string]string `json:"outputs"`
	Name      string            `json:"name"`
	StepType  string            `json:"step_type"`
	Duration  clock.Duration    `json:"duration"`
	ExitCode  int               `json:"exit_code"`
}

// NewState creates an empty lane state.
func NewState() *State {
	return &State{
		Artifacts:  make(map[string]Artifact),
		Steps:      make(map[string]StepResult),
		Provenance: make(map[string]ProvenanceRecord),
	}
}

// RecordProvenance stores a validated provenance record for a step.
func (s *State) RecordProvenance(stepName string, rec ProvenanceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.Provenance[stepName]; exists {
		return fmt.Errorf("provenance for step %q already recorded", stepName)
	}
	s.Provenance[stepName] = rec
	return nil
}

// Register adds an artifact to the state under "step_name.output_name".
func (s *State) Register(stepName, outputName string, a Artifact) error {
	key := stepName + "." + outputName
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.Artifacts[key]; exists {
		return fmt.Errorf("artifact %q already registered", key)
	}
	if a.Digest.IsZero() {
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

// CollectProvenance walks the DAG backwards from fromStep and returns
// all provenance records of transitive predecessors, sorted by step name
// for deterministic attestation output.
func (s *State) CollectProvenance(dag *DAG, fromStep string) []ProvenanceRecord {
	if dag == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	visited := map[string]bool{}
	var walk func(name string)
	walk = func(name string) {
		if visited[name] {
			return
		}
		visited[name] = true
		for _, dep := range dag.edges[name] {
			walk(dep)
		}
	}
	walk(fromStep)
	delete(visited, fromStep) // exclude the deploy step itself

	var names []string
	for n := range visited {
		if _, ok := s.Provenance[n]; ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	out := make([]ProvenanceRecord, 0, len(names))
	for _, n := range names {
		out = append(out, s.Provenance[n])
	}
	return out
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
