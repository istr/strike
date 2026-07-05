package lane

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/output"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/provenance"
)

// State holds one write-once record per step. Each step owns its record and
// fills its fields during its own execution phases; a successor reads a
// predecessor's record only after the predecessor has run, so there is no
// shared mutable state and no central lock. Output references use the
// producer's canonical output ref (OutputRef.Ref, "step_name.output_name").
type State struct {
	records map[primitive.Identifier]*StepRecord
}

// StepRecord is the run status one step contributes. A field is absent (nil)
// until the owning step's corresponding phase fills it, so the presence of a
// field is itself information: a build step carries a spec hash, outputs, and
// network records; a deploy step carries a result; provenance is present only
// for steps that declare it.
type StepRecord struct {
	Provenance provenance.Record                      `json:"provenance,omitempty"`
	SpecHash   *primitive.Digest                      `json:"specHash,omitempty"`
	Outputs    map[primitive.Identifier]output.Handle `json:"outputs,omitempty"`
	Result     *StepResult                            `json:"result,omitempty"`
	Network    *capsule.Records                       `json:"network,omitempty"`
}

// StepResult records execution metadata for a completed step.
type StepResult struct {
	StartedAt clock.Time           `json:"startedAt"`
	Outputs   map[string]string    `json:"outputs"`
	ID        primitive.Identifier `json:"id"`
	StepType  string               `json:"stepType"`
	Duration  clock.Duration       `json:"duration"`
	ExitCode  int                  `json:"exitCode"`
}

// NewState creates an empty lane state.
func NewState() *State {
	return &State{records: map[primitive.Identifier]*StepRecord{}}
}

// record returns the step's record, creating an empty one on first access.
func (s *State) record(stepID primitive.Identifier) *StepRecord {
	rec, ok := s.records[stepID]
	if !ok {
		rec = &StepRecord{}
		s.records[stepID] = rec
	}
	return rec
}

// Register stores the resolved output handle in the producer step's record,
// keyed by output id. The handle carries the digest-pinned image reference
// produced by the normalize round-trip (ADR-046).
func (s *State) Register(stepID, outputID primitive.Identifier, h output.Handle) error {
	ref := OutputRef{Step: stepID, Output: outputID}.Ref()
	if h.ImageRef() == "" {
		return fmt.Errorf("output %q: imageRef is required", ref)
	}
	rec := s.record(stepID)
	if rec.Outputs == nil {
		rec.Outputs = map[primitive.Identifier]output.Handle{}
	}
	if _, exists := rec.Outputs[outputID]; exists {
		return fmt.Errorf("output %q already registered", ref)
	}
	rec.Outputs[outputID] = h
	return nil
}

// Resolve looks up an output handle by its producer's canonical output ref
// (OutputRef.Ref, "step_name.output_name"). The ref is split at the first dot
// into the producer step and its output id.
func (s *State) Resolve(ref string) (output.Handle, error) {
	step, outputID, _ := strings.Cut(ref, ".")
	if rec, ok := s.records[primitive.Identifier(step)]; ok {
		if h, hok := rec.Outputs[primitive.Identifier(outputID)]; hok {
			return h, nil
		}
	}
	return nil, fmt.Errorf("output %q not found; available: %v", ref, s.outputKeys())
}

// RecordProvenance stores a validated provenance record in the step's record.
func (s *State) RecordProvenance(stepID primitive.Identifier, rec provenance.Record) error {
	r := s.record(stepID)
	if r.Provenance != nil {
		return fmt.Errorf("provenance for step %q already recorded", stepID)
	}
	r.Provenance = rec
	return nil
}

// RecordStep stores the result of a completed step in its record.
func (s *State) RecordStep(r StepResult) {
	s.record(r.ID).Result = &r
}

// RecordSpecHash stores a step's spec hash (its content-addressed cache key)
// in its record.
func (s *State) RecordSpecHash(stepID primitive.Identifier, hash primitive.Digest) {
	s.record(stepID).SpecHash = &hash
}

// SpecHash returns a step's recorded spec hash, or the zero digest when the
// step has none (a deploy step, or a predecessor not yet recorded).
func (s *State) SpecHash(stepID primitive.Identifier) primitive.Digest {
	if rec, ok := s.records[stepID]; ok && rec.SpecHash != nil {
		return *rec.SpecHash
	}
	return ""
}

// RecordNetwork stores a step's captured network records in its record.
func (s *State) RecordNetwork(stepID primitive.Identifier, recs capsule.Records) {
	s.record(stepID).Network = &recs
}

// Network returns a step's recorded network records, if any.
func (s *State) Network(stepID primitive.Identifier) (capsule.Records, bool) {
	if rec, ok := s.records[stepID]; ok && rec.Network != nil {
		return *rec.Network, true
	}
	return capsule.Records{}, false
}

// CollectProvenance walks the DAG backwards from fromStep and returns all
// provenance records of transitive predecessors, sorted by step name for
// deterministic attestation output.
func (s *State) CollectProvenance(dag *DAG, fromStep primitive.Identifier) []provenance.Record {
	if dag == nil {
		return []provenance.Record{}
	}
	var names []primitive.Identifier
	for n := range dag.predecessors(fromStep, false) {
		if rec, ok := s.records[n]; ok && rec.Provenance != nil {
			names = append(names, n)
		}
	}
	slices.Sort(names)

	out := make([]provenance.Record, 0, len(names))
	for _, n := range names {
		out = append(out, s.records[n].Provenance)
	}
	return out
}

// JSON serializes the per-step records for debugging and attestation
// round-trips.
func (s *State) JSON() ([]byte, error) {
	return json.MarshalIndent(s.records, "", "  ")
}

func (s *State) outputKeys() []string {
	var keys []string
	for step, rec := range s.records {
		for out := range rec.Outputs {
			keys = append(keys, OutputRef{Step: step, Output: out}.Ref())
		}
	}
	return keys
}
