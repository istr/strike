package executor_test

import (
	"context"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

// orderEngine records, in order, the engine calls the step execution makes
// that bear on image materialization.
type orderEngine struct {
	container.Engine
	present   map[string]bool
	inspectID string
	calls     []string
}

func (e *orderEngine) ImageExists(_ context.Context, ref string) (bool, error) {
	e.calls = append(e.calls, "exists "+ref)
	return e.present[ref], nil
}

func (e *orderEngine) ImageLoad(_ context.Context, input io.Reader) (string, error) {
	if _, err := io.Copy(io.Discard, input); err != nil {
		return "", err
	}
	e.calls = append(e.calls, "load")
	return "loaded", nil
}

func (e *orderEngine) ImageInspect(_ context.Context, ref string) (*container.ImageInfo, error) {
	e.calls = append(e.calls, "inspect "+ref)
	return &container.ImageInfo{ID: e.inspectID}, nil
}

func (e *orderEngine) ContainerRunHeld(_ context.Context, opts container.RunOpts, _ []container.Seed) (string, int, error) {
	e.calls = append(e.calls, "create "+string(opts.Image))
	return "ctr", 0, nil
}

func (e *orderEngine) Identity() *container.EngineIdentity {
	return &container.EngineIdentity{Runtime: &container.RuntimeInfo{OS: "linux", Arch: "amd64"}}
}

// pushTestImage pushes a one-layer image into an in-process registry and
// returns its digest-pinned reference and config digest.
func pushTestImage(t *testing.T) (primitive.ImageRef, string) {
	t.Helper()
	srv := httptest.NewServer(ggcrregistry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	img, err = mutate.AppendLayers(img, static.NewLayer([]byte("step rootfs"), types.OCILayer))
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	repo := "localhost:" + u.Port() + "/t/step"
	tag, err := name.ParseReference(repo + ":pushed")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if wErr := remote.Write(tag, img); wErr != nil {
		t.Fatalf("push: %v", wErr)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	cfg, err := img.ConfigName()
	if err != nil {
		t.Fatalf("config digest: %v", err)
	}
	return primitive.ImageRef(repo + "@" + digest.String()), cfg.Hex
}

func runStep(t *testing.T, eng *orderEngine, image primitive.ImageRef, imageRef string) error {
	t.Helper()
	caps, caVolume := specgenTestCapsule(t)
	r := executor.Run{
		Engine:   eng,
		Capsule:  caps,
		CAVolume: caVolume,
		ImageRef: imageRef,
		Step:     &lane.Step{ID: "step", Image: &image, Args: []string{"true"}},
	}
	_, err := r.Execute(context.Background())
	return err
}

func TestExecute_MaterializesAbsentImageBeforeCreate(t *testing.T) {
	ref, cfg := pushTestImage(t)
	eng := &orderEngine{inspectID: cfg}
	if err := runStep(t, eng, ref, ""); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	want := []string{"exists " + string(ref), "load", "inspect " + string(ref), "create " + string(ref)}
	if strings.Join(eng.calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v, want %v", eng.calls, want)
	}
}

func TestExecute_PresentImageIsNotFetched(t *testing.T) {
	const declared = "localhost:1/t/present@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	eng := &orderEngine{present: map[string]bool{declared: true}}
	if err := runStep(t, eng, primitive.NewImageRef(declared), ""); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	want := []string{"exists " + declared, "create " + declared}
	if strings.Join(eng.calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v, want %v", eng.calls, want)
	}
}

func TestExecute_LaneGeneratedImageIsNotMaterialized(t *testing.T) {
	declared := primitive.ImageRef("localhost:1/t/declared@sha256:0000000000000000000000000000000000000000000000000000000000000000")
	producer := "localhost/strike/lane/build@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	eng := &orderEngine{}
	if err := runStep(t, eng, declared, producer); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	want := []string{"create " + producer}
	if strings.Join(eng.calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v, want %v", eng.calls, want)
	}
}

func TestExecute_FailedFetchCreatesNothing(t *testing.T) {
	srv := httptest.NewServer(ggcrregistry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	declared := "localhost:" + u.Port() + "/t/absent@sha256:0000000000000000000000000000000000000000000000000000000000000001"
	eng := &orderEngine{}
	err = runStep(t, eng, primitive.NewImageRef(declared), "")
	if err == nil {
		t.Fatal("Execute = nil error for an image the registry does not hold")
	}
	if !strings.Contains(err.Error(), declared) || !strings.Contains(err.Error(), "fetch") {
		t.Errorf("error = %q, want it to name the reference and the fetch", err)
	}
	for _, c := range eng.calls {
		if strings.HasPrefix(c, "create") || c == "load" {
			t.Errorf("calls = %v: nothing may be loaded or created after a failed fetch", eng.calls)
		}
	}
}

// The seed image path is engine-internal (ensureSeedImage) and the pack base
// is fetched by the control plane without touching the engine store; neither
// passes through Run.Execute, so neither can reach the materialization. This
// is stated here, not tested: there is no call to count.
