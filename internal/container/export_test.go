package container

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// PodmanRawGet fetches a raw response from the engine for integration tests.
// It accesses the internal HTTP client and base URL of the podman engine.
func PodmanRawGet(ctx context.Context, eng Engine, path string) ([]byte, error) {
	pe, ok := eng.(*podmanEngine)
	if !ok {
		panic("PodmanRawGet: engine is not *podmanEngine")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pe.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pe.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("raw get %s: %w", path, err)
	}
	defer warnClose(resp.Body, "raw get")
	return io.ReadAll(resp.Body)
}

// ContainerInspectInfo holds fields decoded from the libpod container
// inspect response. Used by integration tests to verify schema alignment.
type ContainerInspectInfo struct {
	Image  string                       `json:"Image"`
	ID     string                       `json:"Id"`
	Config ContainerInspectConfigFields `json:"Config"`
	State  ContainerInspectStateFields  `json:"State"`
}

// ContainerInspectStateFields holds the State sub-object fields.
type ContainerInspectStateFields struct {
	Status   string `json:"Status"`
	Running  bool   `json:"Running"`
	ExitCode int    `json:"ExitCode"`
}

// ContainerInspectConfigFields holds the Config sub-object fields.
type ContainerInspectConfigFields struct {
	User       string   `json:"User"`
	WorkingDir string   `json:"WorkingDir"`
	Entrypoint []string `json:"Entrypoint"`
	Cmd        []string `json:"Cmd"`
}

// PodmanContainerCreate exposes containerCreate for integration tests.
func PodmanContainerCreate(ctx context.Context, eng Engine, opts RunOpts) (string, error) {
	pe, ok := eng.(*podmanEngine)
	if !ok {
		panic("PodmanContainerCreate: engine is not *podmanEngine")
	}
	return pe.containerCreate(ctx, opts)
}

// PodmanContainerInspect fetches and decodes the libpod container inspect
// response. Defined here (not in production code) because it is only used
// by integration tests.
func PodmanContainerInspect(ctx context.Context, eng Engine, id string) (*ContainerInspectInfo, error) {
	pe, ok := eng.(*podmanEngine)
	if !ok {
		panic("PodmanContainerInspect: engine is not *podmanEngine")
	}
	u := pe.base + "/containers/" + id + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := pe.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("container inspect %s: %w", id, err)
	}
	defer warnClose(resp.Body, "container inspect")
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("container inspect %s: status %d", id, resp.StatusCode)
	}
	var info ContainerInspectInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("container inspect %s: decode: %w", id, err)
	}
	return &info, nil
}

// PodmanContainerRemove exposes containerRemove for integration tests.
func PodmanContainerRemove(ctx context.Context, eng Engine, id string) error {
	pe, ok := eng.(*podmanEngine)
	if !ok {
		panic("PodmanContainerRemove: engine is not *podmanEngine")
	}
	return pe.containerRemove(ctx, id)
}
