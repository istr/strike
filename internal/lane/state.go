package lane

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/istr/strike/internal/clock"
)

// State tracks outputs and step results across lane execution.
// Output references use the producer's canonical output ref as the
// key (OutputRef.Ref, "step_name.output_name").
type State struct {
	Outputs    map[string]OutputHandle     `json:"outputs"`
	Steps      map[string]StepResult       `json:"steps"`
	Provenance map[string]ProvenanceRecord `json:"provenance"`
	mu         sync.RWMutex
}

// StepResult records execution metadata for a completed step.
type StepResult struct {
	StartedAt clock.Time        `json:"startedAt"`
	Inputs    map[string]string `json:"inputs"`
	Outputs   map[string]string `json:"outputs"`
	Name      string            `json:"name"`
	StepType  string            `json:"stepType"`
	Duration  clock.Duration    `json:"duration"`
	ExitCode  int               `json:"exitCode"`
}

// NewState creates an empty lane state.
func NewState() *State {
	return &State{
		Outputs:    make(map[string]OutputHandle),
		Steps:      make(map[string]StepResult),
		Provenance: make(map[string]ProvenanceRecord),
	}
}

// RecordProvenance stores a validated provenance record for a step.
func (s *State) RecordProvenance(stepID string, rec ProvenanceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.Provenance[stepID]; exists {
		return fmt.Errorf("provenance for step %q already recorded", stepID)
	}
	s.Provenance[stepID] = rec
	return nil
}

// Register stores the resolved output handle under the producer's canonical
// output ref (OutputRef.Ref, "step_name.output_name"). The handle carries the
// digest-pinned image reference produced by the normalize round-trip (ADR-046).
func (s *State) Register(stepID, outputID string, h OutputHandle) error {
	key := OutputRef{Step: Identifier(stepID), Output: Identifier(outputID)}.Ref()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.Outputs[key]; exists {
		return fmt.Errorf("output %q already registered", key)
	}
	if h.ImageRef() == "" {
		return fmt.Errorf("output %q: imageRef is required", key)
	}
	s.Outputs[key] = h
	return nil
}

// Resolve looks up an output handle by its producer's canonical output ref
// (OutputRef.Ref, "step_name.output_name").
func (s *State) Resolve(ref string) (OutputHandle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.Outputs[ref]
	if !ok {
		return nil, fmt.Errorf("output %q not found; available: %v", ref, s.outputKeys())
	}
	return h, nil
}

// CollectProvenance walks the DAG backwards from fromStep and returns
// all provenance records of transitive predecessors, sorted by step name
// for deterministic attestation output.
func (s *State) CollectProvenance(dag *DAG, fromStep string) []ProvenanceRecord {
	if dag == nil {
		return []ProvenanceRecord{}
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

func (s *State) outputKeys() []string {
	keys := make([]string, 0, len(s.Outputs))
	for k := range s.Outputs {
		keys = append(keys, k)
	}
	return keys
}
