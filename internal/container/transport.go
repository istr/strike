package container

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

func newHTTPClient(addr string) *http.Client {
	transport := &http.Transport{
		DisableCompression: true,
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
	}

	if strings.HasPrefix(addr, "unix://") {
		sockPath := strings.TrimPrefix(addr, "unix://")
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sockPath)
		}
	}
	// For tcp:// addresses, the default dialer works.

	return &http.Client{Transport: transport}
}

// apiBase returns the HTTP base URL for API requests.
// For Unix sockets, the host is irrelevant (kernel routes by socket path),
// but http.Request requires a valid URL.
func apiBase(addr string) string {
	if strings.HasPrefix(addr, "unix://") {
		return "http://d/v5.0.0/libpod"
	}
	// tcp://host:port -> http://host:port/v5.0.0/libpod
	host := strings.TrimPrefix(addr, "tcp://")
	return "http://" + host + "/v5.0.0/libpod"
}
