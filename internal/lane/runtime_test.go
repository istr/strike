package lane_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/output"
	"github.com/istr/strike/internal/primitive"
)

// newRuntime builds a lane.Runtime whose node index is exactly ids, wired as
// independent (edgeless) nodes. It is enough for the record-store tests that
// register and read records directly, without running the scheduler.
func newRuntime(t *testing.T, ids ...primitive.Identifier) *lane.Runtime {
	t.Helper()
	return lane.NewRuntime(buildDAG(t, ids...))
}

// buildDAG builds a DAG from bare steps with the given ids and no edges.
func buildDAG(t *testing.T, ids ...primitive.Identifier) *lane.DAG {
	t.Helper()
	steps := make([]lane.Step, len(ids))
	for i, id := range ids {
		steps[i] = lane.Step{ID: id}
	}
	return buildLaneDAG(t, &lane.Lane{Steps: steps})
}

// buildLaneDAG indexes and builds p into a DAG.
func buildLaneDAG(t *testing.T, p *lane.Lane) *lane.DAG {
	t.Helper()
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return dag
}

func TestRegisterAndResolve(t *testing.T) {
	s := newRuntime(t, "build")

	imageRef := "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000"
	h := output.ImageHandle{Ref: imageRef}

	if err := s.Register("build", "binary", h); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := s.Resolve(lane.OutputRef{Step: "build", Output: "binary"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ImageRef() != imageRef {
		t.Errorf("imageRef = %q, want %q", got.ImageRef(), imageRef)
	}
	digest, err := output.ManifestDigest(got)
	if err != nil {
		t.Fatalf("ManifestDigest: %v", err)
	}
	want := primitive.DigestFromHex("abc1230000000000000000000000000000000000000000000000000000000000")
	if digest != want {
		t.Errorf("digest = %q, want %q", digest, want)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	s := newRuntime(t, "build")
	h := output.ImageHandle{Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000"}

	if err := s.Register("build", "binary", h); err != nil {
		t.Fatal(err)
	}
	if err := s.Register("build", "binary", h); err == nil {
		t.Fatal("expected error on duplicate register")
	}
}

func TestRegisterMissingImageRef(t *testing.T) {
	s := newRuntime(t, "build")
	h := output.ImageHandle{}

	if err := s.Register("build", "binary", h); err == nil {
		t.Fatal("expected error on missing image ref")
	}
}

func TestResolveMissing(t *testing.T) {
	s := newRuntime(t)
	_, err := s.Resolve(lane.OutputRef{Step: "nonexistent", Output: "output"})
	if err == nil {
		t.Fatal("expected error on missing reference")
	}
}

func TestRecordStep(t *testing.T) {
	s := newRuntime(t, "build")
	s.RecordStep(lane.StepResult{
		ID:        "build",
		StepType:  "run",
		StartedAt: primitive.Timestamp("2024-01-01T00:00:00Z"),
		Duration:  primitive.Duration("5s"),
		Outputs:   map[string]string{"binary": "sha256:222"},
		ExitCode:  0,
	})

	var m map[string]struct {
		Result *lane.StepResult `json:"result"`
	}
	data, err := s.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rec, ok := m["build"]
	if !ok || rec.Result == nil {
		t.Fatal("step result not recorded")
	}
	if rec.Result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", rec.Result.ExitCode)
	}
}

func TestRuntimeJSON(t *testing.T) {
	s := newRuntime(t, "build")
	if err := s.Register("build", "binary", output.ImageHandle{
		Ref: "localhost/test/build@sha256:abc1230000000000000000000000000000000000000000000000000000000000",
	}); err != nil {
		t.Fatal(err)
	}
	s.RecordStep(lane.StepResult{
		ID:       "build",
		StepType: "run",
		Outputs:  map[string]string{"binary": "sha256:abc1230000000000000000000000000000000000000000000000000000000000"},
	})

	data, err := s.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var m map[string]map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	build, ok := m["build"]
	if !ok {
		t.Fatal("missing build step in JSON")
	}
	if _, ok := build["outputs"]; !ok {
		t.Error("missing outputs in build record")
	}
	if _, ok := build["result"]; !ok {
		t.Error("missing result in build record")
	}
}

// TestRuntimeRunPublishesToSuccessor exercises the release/acquire edge: a
// producer writes its record and the walk publishes it before decrementing the
// consumer, so the consumer's fire acquire-loads a fully-published record.
func TestRuntimeRunPublishesToSuccessor(t *testing.T) {
	// build -> consume (consume declares image_from: build).
	rt := lane.NewRuntime(buildLaneDAG(t, &lane.Lane{Steps: []lane.Step{
		{ID: "build"},
		{ID: "consume", ImageFromStep: primitive.IdentifierPtr("build")},
	}}))

	buildHash := primitive.DigestFromHex("1111111111111111000000000000000000000000000000000000000000000000")
	var consumeSaw primitive.Digest
	run := func(step primitive.Identifier) error {
		switch step {
		case "build":
			rt.RecordSpecHash("build", buildHash)
		case "consume":
			consumeSaw = rt.SpecHash("build")
		}
		return nil
	}
	if err := rt.Run(run); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if consumeSaw != buildHash {
		t.Errorf("consumer saw spec hash %q, want %q (predecessor publish not observed)",
			consumeSaw, buildHash)
	}
}

// TestRuntimeRunFailFastBranchLocal is the gate-6 concurrency test: a lane with
// a failing step and an independent branch runs the independent branch to
// completion, does not execute the failed branch's descendants, reports the
// failure, and terminates without deadlock.
func TestRuntimeRunFailFastBranchLocal(t *testing.T) {
	// Two disjoint branches:
	//   fail -> after-fail   (after-fail must be short-circuited, never run)
	//   ok-a -> ok-b         (both must run to completion)
	rt := lane.NewRuntime(buildLaneDAG(t, &lane.Lane{Steps: []lane.Step{
		{ID: "fail"},
		{ID: "after-fail", ImageFromStep: primitive.IdentifierPtr("fail")},
		{ID: "ok-a"},
		{ID: "ok-b", ImageFromStep: primitive.IdentifierPtr("ok-a")},
	}}))

	ran := map[primitive.Identifier]*atomic.Bool{
		"fail": {}, "after-fail": {}, "ok-a": {}, "ok-b": {},
	}
	wantErr := errors.New("step failed")
	run := func(step primitive.Identifier) error {
		ran[step].Store(true)
		if step == "fail" {
			return wantErr
		}
		return nil
	}

	// A correct walk always drains; guard against a deadlock so a regression
	// fails fast instead of hanging the suite.
	done := make(chan error, 1)
	go func() { done <- rt.Run(run) }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*clock.Second)
	defer cancel()

	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		t.Fatal("Runtime.Run deadlocked: the walk did not drain")
	}

	if err == nil {
		t.Fatal("Run returned nil, want the failed step's error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Run error = %v, want it to wrap %v", err, wantErr)
	}
	if !ran["fail"].Load() {
		t.Error("failed step did not run its body")
	}
	if ran["after-fail"].Load() {
		t.Error("descendant of a failed step ran; fail-fast is not branch-local")
	}
	if !ran["ok-a"].Load() || !ran["ok-b"].Load() {
		t.Error("independent branch did not run to completion")
	}
}
