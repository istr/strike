package main

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

// mockEngine implements container.Engine for testing runContext methods.
type mockEngine struct {
	loadErr        error
	imageExistsErr error
	pullErr        error
	pushErr        error
	pingErr        error
	inspectErr     error
	tagErr         error
	runErr         error
	saveErr        error
	inspectRV      *container.ImageInfo
	identity       *container.EngineIdentity
	saveTars       map[string][]byte // tag -> OCI tar bytes for ImageSave
	saveCalls      map[string]int    // tag -> number of ImageSave calls
	loadRV         string
	runExitCode    int
	imageExistsRV  bool
}

func (m *mockEngine) Ping(context.Context) error { return m.pingErr }

func (m *mockEngine) ImageExists(_ context.Context, _ string) (bool, error) {
	return m.imageExistsRV, m.imageExistsErr
}

func (m *mockEngine) ImagePull(context.Context, string) error { return m.pullErr }

func (m *mockEngine) ImagePush(context.Context, string) error { return m.pushErr }

func (m *mockEngine) ImageLoad(_ context.Context, _ io.Reader) (string, error) {
	return m.loadRV, m.loadErr
}

func (m *mockEngine) ImageInspect(_ context.Context, _ string) (*container.ImageInfo, error) {
	return m.inspectRV, m.inspectErr
}

func (m *mockEngine) ImageTag(context.Context, string, string) error { return m.tagErr }

func (m *mockEngine) ImageSave(_ context.Context, tag string) (io.ReadCloser, error) {
	if m.saveCalls == nil {
		m.saveCalls = map[string]int{}
	}
	m.saveCalls[tag]++
	if m.saveErr != nil {
		return nil, m.saveErr
	}
	if m.saveTars != nil {
		if data, ok := m.saveTars[tag]; ok {
			return io.NopCloser(bytes.NewReader(data)), nil
		}
	}
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (m *mockEngine) ContainerRun(_ context.Context, _ container.RunOpts) (int, error) {
	return m.runExitCode, m.runErr
}

func (m *mockEngine) TLSIdentity() *container.TLSIdentity { return nil }

func (m *mockEngine) Identity() *container.EngineIdentity { return m.identity }

func (m *mockEngine) Info(context.Context) error { return nil }
func (m *mockEngine) ContainerRunHeld(_ context.Context, _ container.RunOpts, _ []container.Seed) (string, int, error) {
	return "", 0, nil
}

func (m *mockEngine) ContainerArchive(_ context.Context, _, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (m *mockEngine) ContainerCommit(_ context.Context, _ string) (string, error) {
	return "sha256:mock-committed-image", nil
}
func (m *mockEngine) ContainerRemove(_ context.Context, _ string) error             { return nil }
func (m *mockEngine) VolumeCreate(_ context.Context, _ string) error                { return nil }
func (m *mockEngine) SeedVolumes(_ context.Context, _ []container.VolumeSeed) error { return nil }
func (m *mockEngine) VolumeRemove(_ context.Context, _ string) error                { return nil }

// buildTestDAG runs lane.IndexSteps and lane.Build on p and fails the test on
// error, returning the DAG and its step index.
func buildTestDAG(t *testing.T, p *lane.Lane) (*lane.DAG, map[primitive.Identifier]*lane.Step) {
	t.Helper()
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatalf("lane.Build: %v", err)
	}
	return dag, index
}

// loadLane wires p into rc: its lane, DAG, step index, and a Runtime whose node
// index covers every step. Mirrors cmdRun's setup for the unit tests that
// record and read a single step's inputs and outputs without running the walk.
func (rc *runContext) loadLane(t *testing.T, p *lane.Lane) {
	t.Helper()
	rc.lane = p
	rc.dag, rc.stepIndex = buildTestDAG(t, p)
	rc.runtime = lane.NewRuntime(rc.dag)
}

// runtimeForSteps builds a lane.Runtime whose node index is exactly ids, wired
// as independent nodes, for tests that record to a step id without a full lane.
func runtimeForSteps(t *testing.T, ids ...primitive.Identifier) *lane.Runtime {
	t.Helper()
	steps := make([]lane.Step, len(ids))
	for i, id := range ids {
		steps[i] = lane.Step{ID: id}
	}
	p := &lane.Lane{Steps: steps}
	index, err := lane.IndexSteps(p)
	if err != nil {
		t.Fatalf("lane.IndexSteps: %v", err)
	}
	dag, err := lane.Build(p, index)
	if err != nil {
		t.Fatalf("lane.Build: %v", err)
	}
	return lane.NewRuntime(dag)
}
