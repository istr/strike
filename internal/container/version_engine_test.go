package container_test

import (
	"context"
	"io"
	"testing"

	"github.com/istr/strike/internal/container"
)

// stubEngine is a minimal Engine for RequireVersion tests.
type stubEngine struct {
	identity *container.EngineIdentity
}

func (s *stubEngine) ImageExists(context.Context, string) (bool, error)    { return false, nil }
func (s *stubEngine) ImagePull(context.Context, string) error              { return nil }
func (s *stubEngine) ImagePush(context.Context, string) error              { return nil }
func (s *stubEngine) ImageLoad(context.Context, io.Reader) (string, error) { return "", nil }
func (s *stubEngine) ImageInspect(context.Context, string) (*container.ImageInfo, error) {
	return nil, nil
}
func (s *stubEngine) ImageTag(context.Context, string, string) error               { return nil }
func (s *stubEngine) ImageSave(context.Context, string) (io.ReadCloser, error)     { return nil, nil }
func (s *stubEngine) ContainerRun(context.Context, container.RunOpts) (int, error) { return 0, nil }
func (s *stubEngine) Ping(context.Context) error                                   { return nil }
func (s *stubEngine) TLSIdentity() *container.TLSIdentity                          { return nil }
func (s *stubEngine) Identity() *container.EngineIdentity                          { return s.identity }
func (s *stubEngine) Info(context.Context) error                                   { return nil }

func TestRequireVersion_NilIdentity(t *testing.T) {
	e := &stubEngine{identity: nil}
	if err := container.RequireVersion(e, "5.0.0"); err == nil {
		t.Error("expected error for nil identity")
	}
}

func TestRequireVersion_NilRuntime(t *testing.T) {
	e := &stubEngine{identity: &container.EngineIdentity{}}
	if err := container.RequireVersion(e, "5.0.0"); err == nil {
		t.Error("expected error for nil runtime")
	}
}

func TestRequireVersion_EmptyVersion(t *testing.T) {
	e := &stubEngine{identity: &container.EngineIdentity{
		Runtime: &container.RuntimeInfo{Version: ""},
	}}
	if err := container.RequireVersion(e, "5.0.0"); err == nil {
		t.Error("expected error for empty version")
	}
}

func TestRequireVersion_BelowMinimum(t *testing.T) {
	e := &stubEngine{identity: &container.EngineIdentity{
		Runtime: &container.RuntimeInfo{Version: "4.9.9"},
	}}
	if err := container.RequireVersion(e, "5.0.0"); err == nil {
		t.Error("expected error for version below minimum")
	}
}

func TestRequireVersion_AtMinimum(t *testing.T) {
	e := &stubEngine{identity: &container.EngineIdentity{
		Runtime: &container.RuntimeInfo{Version: "5.0.0"},
	}}
	if err := container.RequireVersion(e, "5.0.0"); err != nil {
		t.Errorf("unexpected error at minimum version: %v", err)
	}
}

func TestRequireVersion_AboveMinimum(t *testing.T) {
	e := &stubEngine{identity: &container.EngineIdentity{
		Runtime: &container.RuntimeInfo{Version: "5.4.2"},
	}}
	if err := container.RequireVersion(e, "5.0.0"); err != nil {
		t.Errorf("unexpected error above minimum version: %v", err)
	}
}
