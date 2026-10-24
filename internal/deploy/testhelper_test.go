package deploy_test

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

// newRuntime builds a lane.Runtime whose node index is exactly ids, wired as
// independent nodes. Deploy tests register artifact outputs and a deploy step's
// result against these nodes without running the scheduler; tests that need the
// real dependency edges build the Runtime from a full DAG instead.
func newRuntime(t *testing.T, ids ...primitive.Identifier) *lane.Runtime {
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

// writeJSON encodes v as JSON to w, failing the test on error.
func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("test handler: encode JSON: %v", err)
	}
}

// isContainerInspect reports whether r is an inspect of one container or one
// image (GET /containers/{id}/json, GET /images/{ref}/json), not a list.
func isContainerInspect(r *http.Request) bool {
	p := r.URL.Path
	if r.Method != http.MethodGet || !strings.HasSuffix(p, "/json") ||
		strings.HasSuffix(p, "/containers/json") || strings.HasSuffix(p, "/images/json") {
		return false
	}
	return strings.Contains(p, "/containers/") || strings.Contains(p, "/images/")
}

// writeHardenedInspect answers a container or image inspect with the fields
// the post-create profile check reads, as the engine reports them for a
// container created with the hardened profile and the env given.
func writeHardenedInspect(t *testing.T, w http.ResponseWriter, env ...string) {
	t.Helper()
	writeJSON(t, w, hardenedInspect(env...))
}

// hardenedInspect is the inspect body writeHardenedInspect sends.
func hardenedInspect(env ...string) map[string]any {
	return map[string]any{
		"Config": map[string]any{"Env": env},
		"HostConfig": map[string]any{
			"ReadonlyRootfs": true,
			"SecurityOpt":    []string{"no-new-privileges"},
			"HostsFile":      "none",
			"DnsSearch":      []string{"."},
			"ExtraHosts":     []string{"host.containers.internal:127.0.0.1", "host.docker.internal:127.0.0.1"},
			"IDMappings":     map[string]any{"UidMap": []string{"0:1:1000", "1000:0:1", "1001:1001:64536"}},
		},
	}
}

// mustWrite writes data to w, failing the test on error.
func mustWrite(t *testing.T, w http.ResponseWriter, data []byte) {
	t.Helper()
	if _, err := w.Write(data); err != nil {
		t.Fatalf("test handler: write: %v", err)
	}
}

// streamFrame builds a Podman multiplexed log frame (header + payload).
// stream: 1=stdout, 2=stderr.
func streamFrame(stream byte, payload []byte) []byte {
	frame := make([]byte, 8+len(payload))
	frame[0] = stream
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload))) // #nosec G115 -- test data is always small
	copy(frame[8:], payload)
	return frame
}
