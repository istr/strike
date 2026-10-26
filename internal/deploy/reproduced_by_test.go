package deploy_test

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/output"
	"github.com/istr/strike/internal/primitive"
)

// Manifest and config digests of the two images a reproduction gate compares.
// Only their form matters: the gate reads them off the image handles.
const (
	reproDigestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	reproDigestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	reproConfig  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// TestDeployerExecute_ReproducedBy drives a registry deploy that names a
// reproducedBy step through Execute. The engine counts image exports, the
// first engine call of the push path, answers each with a server error, and
// fails the test on any other call. A deploy whose gate passes reaches the
// export; a deploy whose gate fails returns before it, so nothing is
// captured, exported, pushed or signed.
func TestDeployerExecute_ReproducedBy(t *testing.T) {
	tests := []struct {
		name       string
		armRef     string
		againRef   string
		againCfg   primitive.Digest
		wantErr    []string
		wantExport bool
	}{
		{
			name:       "digests agree",
			armRef:     "localhost/strike/test-lane/build@" + reproDigestA,
			againRef:   "localhost/strike/test-lane/rebuild@" + reproDigestA,
			againCfg:   reproConfig,
			wantErr:    []string{"deploy action failed"},
			wantExport: true,
		},
		{
			name:     "digests differ",
			armRef:   "localhost/strike/test-lane/build@" + reproDigestA,
			againRef: "localhost/strike/test-lane/rebuild@" + reproDigestB,
			againCfg: reproConfig,
			wantErr:  []string{"not reproducible", `step "build" built ` + reproDigestA, `step "rebuild" built ` + reproDigestB},
		},
		{
			name:     "second build not produced in this run",
			armRef:   "localhost/strike/test-lane/build@" + reproDigestA,
			againRef: "localhost/strike/test-lane/rebuild@" + reproDigestA,
			wantErr:  []string{`step "rebuild" holds no image produced in this run`},
		},
		{
			name:    "second build not registered",
			armRef:  "localhost/strike/test-lane/build@" + reproDigestA,
			wantErr: []string{"reproducedBy", "not found"},
		},
		{
			name:     "image arm reference without digest",
			armRef:   "localhost/strike/test-lane/build",
			againRef: "localhost/strike/test-lane/rebuild@" + reproDigestA,
			againCfg: reproConfig,
			wantErr:  []string{"reproducedBy", "no digest in image ref"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var exports atomic.Int32
			eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/get") {
					exports.Add(1)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				t.Errorf("unexpected engine call: %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}))

			state := newRuntime(t, "build", "rebuild", "publish")
			if err := state.Register("build", "", output.ImageHandle{Ref: tc.armRef, ConfigDigest: reproConfig}); err != nil {
				t.Fatal(err)
			}
			if tc.againRef != "" {
				if err := state.Register("rebuild", "", output.ImageHandle{Ref: tc.againRef, ConfigDigest: tc.againCfg}); err != nil {
					t.Fatal(err)
				}
			}

			method := deploy.DeployRegistryForTest()
			method.ReproducedBy = primitive.IdentifierPtr("rebuild")
			artifacts := map[primitive.Identifier]lane.ArtifactRef{"app": {Step: "build"}}
			step := &lane.Step{
				ID: "publish",
				Deploy: &lane.DeploySpec{
					Method:    method,
					Artifacts: artifacts,
					Recording: lane.StateRecording{
						PreState:  lane.CaptureSet{Captures: []lane.Capture{}},
						PostState: lane.CaptureSet{Captures: []lane.Capture{}},
					},
				},
			}
			d := &deploy.Deployer{
				Engine:       eng,
				ArtifactRefs: artifacts,
				LaneID:       "test-lane",
				StepID:       "publish",
			}

			_, err := d.Execute(context.Background(), step, state)
			if err == nil {
				t.Fatal("Execute succeeded; the engine fails every export, so no case may pass")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Execute error = %v, want it to contain %q", err, want)
				}
			}
			if got := exports.Load() > 0; got != tc.wantExport {
				t.Errorf("image export attempted = %v, want %v", got, tc.wantExport)
			}
		})
	}
}
