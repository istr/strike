package main

import (
	"context"
	"io"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/lane"
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
	inspectRV      *container.ImageInfo
	identity       *container.EngineIdentity
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

func (m *mockEngine) ContainerRun(_ context.Context, _ container.RunOpts) (int, error) {
	return m.runExitCode, m.runErr
}

func (m *mockEngine) TLSIdentity() *container.TLSIdentity { return nil }

func (m *mockEngine) Identity() *container.EngineIdentity { return m.identity }

func (m *mockEngine) Info(context.Context) error { return nil }

// buildTestDAG runs lane.Build on p and fails the test on error.
func buildTestDAG(t *testing.T, p *lane.Lane) *lane.DAG {
	t.Helper()
	dag, err := lane.Build(p)
	if err != nil {
		t.Fatalf("lane.Build: %v", err)
	}
	return dag
}
