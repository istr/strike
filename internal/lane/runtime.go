package lane

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/output"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/provenance"
)

// StepRecord is the run status one step contributes. A field is absent (nil)
// until the owning step's corresponding phase fills it, so the presence of a
// field is itself information: a build step carries a spec hash, outputs, and
// network records; a deploy step carries a result; provenance is present only
// for steps that declare it. Output references use the producer's canonical
// output ref (OutputRef.Ref, "step_name.output_name").
type StepRecord struct {
	Provenance provenance.Record                      `json:"provenance,omitempty"`
	SpecHash   *primitive.Digest                      `json:"specHash,omitempty"`
	Outputs    map[primitive.Identifier]output.Handle `json:"outputs,omitempty"`
	Result     *StepResult                            `json:"result,omitempty"`
	Network    *capsule.Records                       `json:"network,omitempty"`
}

// execNode is one DAG step's execution state and its published record. The
// owning step is its single writer: it fills working during its own phases and
// publishes it with a release-store (record). Every coordination word is
// monotone -- pending decrement-only, failed false->true once, record
// nil->value once -- so the walk needs no lock. preds/succs are the dependency
// links, materialized once by NewRuntime.
type execNode struct {
	err     error                      // single-writer (this node's fire); read post-barrier
	working *StepRecord                // single-writer; built in place by the owning step
	record  atomic.Pointer[StepRecord] // published once (nil->working)
	step    primitive.Identifier
	preds   []*execNode
	succs   []*execNode
	pending atomic.Int64 // in-degree, decrement-only
	failed  atomic.Bool  // false->true once
}

// Runtime holds one write-once record per step on its execNode and drives the
// fire-at-zero walk over the DAG. There is no shared record map: the node index
// is the store, materialized once single-threaded by NewRuntime. Producers
// write only their own node's record and publish it with a release-store;
// consumers acquire-load a predecessor's published record.
type Runtime struct {
	nodes     map[primitive.Identifier]*execNode
	finished  chan struct{}
	remaining atomic.Int64
}

// NewRuntime materializes one execNode per DAG step, wires preds/succs from the
// dependency adjacency, and sets each node's pending to its in-degree. This is
// the single materialization: it is exactly the graph build, single-threaded,
// with no separate pre-population step. A step's working record starts empty
// and is filled in place during that step's own fire.
func NewRuntime(dag *DAG) *Runtime {
	r := &Runtime{nodes: make(map[primitive.Identifier]*execNode, len(dag.index))}
	for step := range dag.index {
		r.nodes[step] = &execNode{step: step, working: &StepRecord{}}
	}
	for step, node := range r.nodes {
		deps := dag.edges[step]
		node.pending.Store(int64(len(deps)))
		for _, dep := range deps {
			node.preds = append(node.preds, r.nodes[dep])
		}
		for _, dependent := range dag.reverse[step] {
			node.succs = append(node.succs, r.nodes[dependent])
		}
	}
	return r
}

// Run drives the fire-at-zero walk: seed every zero-in-degree root, then let
// each completion decrement its successors and fire the ones that reach zero.
// Parallelism is the DAG's antichain width; the container engine is the worker,
// so there is no pool or bound. Run blocks until the monotone remaining counter
// reaches zero and returns the aggregated failure of any node that failed.
func (r *Runtime) Run(run func(primitive.Identifier) error) error {
	if len(r.nodes) == 0 {
		return nil
	}
	r.remaining.Store(int64(len(r.nodes)))
	r.finished = make(chan struct{})
	for _, n := range r.nodes {
		if n.pending.Load() == 0 {
			go r.fire(n, run)
		}
	}
	<-r.finished
	return r.aggregateErr()
}

// fire runs one node and hands off to its successors. Failure is fail-fast but
// branch-local: at the head of its fire a node short-circuits if any
// predecessor failed, and a node whose own step errors takes the same path --
// it marks itself failed, publishes an empty record, decrements its successors,
// and returns without executing. No shared abort state is read, so disjoint
// branches are unaffected. Because a failed node still decrements, every node
// fires and the walk terminates when remaining reaches zero.
func (r *Runtime) fire(n *execNode, run func(primitive.Identifier) error) {
	for _, p := range n.preds {
		if p.failed.Load() {
			n.failed.Store(true)
			break
		}
	}
	if !n.failed.Load() {
		if err := run(n.step); err != nil {
			n.err = err
			n.failed.Store(true)
		}
	}
	// Publish before decrement: the record is fully written, and this
	// release-store is the edge a successor's acquire-load pairs with. The
	// successor decrement below is therefore an acquire/release boundary --
	// every consumer that later fires sees a fully-published predecessor.
	n.record.Store(n.working)
	for _, s := range n.succs {
		if s.pending.Add(-1) == 0 {
			go r.fire(s, run)
		}
	}
	if r.remaining.Add(-1) == 0 {
		close(r.finished)
	}
}

// aggregateErr collects, sorted by step name for determinism, the error of
// every node whose own step failed. Short-circuited nodes (failed because a
// predecessor failed) carry no error and do not contribute, so only root causes
// are reported. Read single-threaded after the walk's barrier.
func (r *Runtime) aggregateErr() error {
	var failed []primitive.Identifier
	for id, n := range r.nodes {
		if n.err != nil {
			failed = append(failed, id)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	slices.Sort(failed)
	errs := make([]error, len(failed))
	for i, id := range failed {
		errs[i] = r.nodes[id].err
	}
	return errors.Join(errs...)
}

// published returns a step node's effective record for a reader: the
// release-stored published record once the owning step has published, or --
// before publication, which for a reader can only be the owning step's own
// in-progress record read from that step's own goroutine -- its working record.
// A predecessor read always takes the published path (a successor fires only
// after the predecessor publishes), so the working fallback is reached only by
// a step reading itself or by a single-threaded caller. Nil when step is not a
// node.
func (r *Runtime) published(step primitive.Identifier) *StepRecord {
	n, ok := r.nodes[step]
	if !ok {
		return nil
	}
	if rec := n.record.Load(); rec != nil {
		return rec
	}
	return n.working
}

// Register stores the resolved output handle in the producer step's record,
// keyed by output id. The handle carries the digest-pinned image reference
// produced by the normalize round-trip (ADR-046). Single-writer: the owning
// step writes its own pre-built node, so there is no map insert.
func (r *Runtime) Register(stepID, outputID primitive.Identifier, h output.Handle) error {
	ref := OutputRef{Step: stepID, Output: outputID}.Ref()
	if h.ImageRef() == "" {
		return fmt.Errorf("output %q: imageRef is required", ref)
	}
	n, ok := r.nodes[stepID]
	if !ok {
		return fmt.Errorf("output %q: step %q is not a lane node", ref, stepID)
	}
	rec := n.working
	if rec.Outputs == nil {
		rec.Outputs = map[primitive.Identifier]output.Handle{}
	}
	if _, exists := rec.Outputs[outputID]; exists {
		return fmt.Errorf("output %q already registered", ref)
	}
	rec.Outputs[outputID] = h
	return nil
}

// Resolve looks up an output handle by its producer's output reference. The
// producer step's published record is acquire-loaded and its output id read
// directly off the typed ref -- no dotted-string round-trip.
func (r *Runtime) Resolve(from OutputRef) (output.Handle, error) {
	if rec := r.published(from.Step); rec != nil {
		if h, ok := rec.Outputs[from.Output]; ok {
			return h, nil
		}
	}
	return nil, fmt.Errorf("output %q not found; available: %v", from.Ref(), r.outputKeys())
}

// RecordProvenance stores a validated provenance record in the step's record.
func (r *Runtime) RecordProvenance(stepID primitive.Identifier, rec provenance.Record) error {
	n, ok := r.nodes[stepID]
	if !ok {
		return fmt.Errorf("provenance for step %q: not a lane node", stepID)
	}
	if n.working.Provenance != nil {
		return fmt.Errorf("provenance for step %q already recorded", stepID)
	}
	n.working.Provenance = rec
	return nil
}

// RecordStep stores the result of a completed step in its record.
func (r *Runtime) RecordStep(res StepResult) {
	if n, ok := r.nodes[res.ID]; ok {
		n.working.Result = &res
	}
}

// RecordSpecHash stores a step's spec hash (its content-addressed cache key)
// in its record.
func (r *Runtime) RecordSpecHash(stepID primitive.Identifier, hash primitive.Digest) {
	if n, ok := r.nodes[stepID]; ok {
		n.working.SpecHash = &hash
	}
}

// SpecHash returns a step's recorded spec hash, or the zero digest when the
// step has none (a deploy step, or a predecessor not yet recorded).
func (r *Runtime) SpecHash(stepID primitive.Identifier) primitive.Digest {
	if rec := r.published(stepID); rec != nil && rec.SpecHash != nil {
		return *rec.SpecHash
	}
	return ""
}

// RecordNetwork stores a step's captured network records in its record.
func (r *Runtime) RecordNetwork(stepID primitive.Identifier, recs capsule.Records) {
	if n, ok := r.nodes[stepID]; ok {
		n.working.Network = &recs
	}
}

// Network returns a step's recorded network records, if any.
func (r *Runtime) Network(stepID primitive.Identifier) (capsule.Records, bool) {
	if rec := r.published(stepID); rec != nil && rec.Network != nil {
		return *rec.Network, true
	}
	return capsule.Records{}, false
}

// CollectProvenance walks the DAG backwards from fromStep and returns all
// provenance records of transitive predecessors, sorted by step name for
// deterministic attestation output. Each predecessor's record is acquire-loaded
// from its published node.
func (r *Runtime) CollectProvenance(dag *DAG, fromStep primitive.Identifier) []provenance.Record {
	if dag == nil {
		return []provenance.Record{}
	}
	var names []primitive.Identifier
	for n := range dag.predecessors(fromStep, false) {
		if rec := r.published(n); rec != nil && rec.Provenance != nil {
			names = append(names, n)
		}
	}
	slices.Sort(names)

	out := make([]provenance.Record, 0, len(names))
	for _, n := range names {
		out = append(out, r.published(n).Provenance)
	}
	return out
}

// JSON serializes the per-step published records for the debug state dump.
// The output is compact (single line, map keys sorted by json), so the caller
// logs it as one entry after passing it through a control-character sanitizer.
// Called single-threaded after the walk's barrier.
func (r *Runtime) JSON() ([]byte, error) {
	records := make(map[primitive.Identifier]*StepRecord, len(r.nodes))
	for step := range r.nodes {
		records[step] = r.published(step)
	}
	return json.Marshal(records)
}

// outputKeys lists the canonical refs of every published output, for the
// "available" diagnostic on a failed Resolve. It reads only published records
// (atomic loads), so it is safe to call while other nodes execute.
func (r *Runtime) outputKeys() []string {
	var keys []string
	for step, n := range r.nodes {
		rec := n.record.Load()
		if rec == nil {
			continue
		}
		for out := range rec.Outputs {
			keys = append(keys, OutputRef{Step: step, Output: out}.Ref())
		}
	}
	return keys
}
