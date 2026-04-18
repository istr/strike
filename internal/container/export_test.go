package container

import (
	"context"
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
