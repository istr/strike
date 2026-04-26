package container

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/istr/strike/internal/clock"
)

// newHTTPClient creates an HTTP client for the given address.
//
// Unix sockets use plain HTTP (kernel-enforced access control).
// TCP always uses TLS. If an explicit CA is configured, only that CA is
// trusted (pinned mode). Otherwise the system CA store is used.
// mTLS is used when client cert and key are provided.
func newHTTPClient(addr string, tlsCfg *TLSConfig) (*http.Client, error) {
	transport := &http.Transport{
		DisableCompression: true,
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * clock.Second,
	}

	switch {
	case strings.HasPrefix(addr, "unix://"):
		sockPath := strings.TrimPrefix(addr, "unix://")
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sockPath)
		}

	case strings.HasPrefix(addr, "tcp://"):
		if !tlsCfg.IsReady() {
			return nil, fmt.Errorf("tcp:// connections require TLS configuration")
		}
		tc, err := tlsCfg.Build()
		if err != nil {
			return nil, fmt.Errorf("engine TLS: %w", err)
		}
		transport.TLSClientConfig = tc

	default:
		return nil, fmt.Errorf("unsupported address scheme: %q (supported: unix://, tcp://)", addr)
	}

	var rt http.RoundTripper = transport
	if os.Getenv("STRIKE_AUDIT") != "" {
		rt = &auditTransport{inner: transport}
	}

	return &http.Client{Transport: rt}, nil
}

// apiBase returns the HTTP base URL for API requests.
// Unix sockets use http:// (kernel routes by socket path, scheme is
// irrelevant to the kernel). TCP always uses https://.
func apiBase(addr string) string {
	if strings.HasPrefix(addr, "unix://") {
		return "http://d/v5.0.0/libpod"
	}
	host := strings.TrimPrefix(addr, "tcp://")
	return "https://" + host + "/v5.0.0/libpod"
}

// auditTransport wraps an http.RoundTripper and logs every request for
// forensic accountability. Enabled via STRIKE_AUDIT=1.
//
// Logs method, path, response status, duration.
// Never logs request bodies (they may contain secrets in container create).
type auditTransport struct {
	inner http.RoundTripper
}

func (a *auditTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := clock.Wall()
	resp, err := a.inner.RoundTrip(req)
	duration := clock.Since(start)

	status := -1
	if resp != nil {
		status = resp.StatusCode
	}
	log.Printf("AUDIT  %s %s -> %d (%s)", // #nosec G706 -- internal engine HTTP request, not user input
		req.Method, req.URL.Path, status, duration.Round(clock.Millisecond))

	return resp, err
}
