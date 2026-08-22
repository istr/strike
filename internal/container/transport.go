package container

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	nettransport "github.com/istr/strike/internal/transport"
)

// apiPath is the libpod API prefix every engine request is built on. It is
// the path component of the base URL, stated once and projected into both
// forms below.
const apiPath = "/v5.0.0/libpod"

// engineAddress is the parsed engine address. Two forms are admitted, and
// they are the two the engine connection identity already distinguishes: a
// unix socket, whose access control is the socket file's own, and an https
// authority, whose transport is TLS because the grammar says so rather than
// because a caller remembered to ask for it. Socket carries the first form,
// Network the second, and Unix says which one is set.
type engineAddress struct {
	Network endpoint.Address
	Socket  primitive.AbsPath
	Unix    bool
}

// parseEngineAddress parses the raw engine address into its admitted forms.
// It is the only place the raw string is inspected: every consumer below
// takes the parsed value, so the scheme is discriminated once and the forms
// it yields are the ones the endpoint and primitive packages already model.
// A plaintext network address has no representation here at all, which is
// what makes the TLS requirement structural rather than a runtime check.
func parseEngineAddress(addr string) (engineAddress, error) {
	if sock, ok := strings.CutPrefix(addr, "unix://"); ok {
		socket := primitive.NewAbsPath(sock)
		if err := socket.Validate(); err != nil {
			return engineAddress{}, fmt.Errorf("engine socket path: %w", err)
		}
		return engineAddress{Socket: socket, Unix: true}, nil
	}
	if strings.HasPrefix(addr, "https://") {
		network, err := endpoint.ParseURL(addr)
		if err != nil {
			return engineAddress{}, err
		}
		if network.Path != nil {
			return engineAddress{}, errors.New("engine address must not carry a path")
		}
		return engineAddress{Network: network}, nil
	}
	return engineAddress{}, fmt.Errorf(
		"unsupported address scheme: %q (supported: unix://, https://)", addr)
}

// newHTTPClient creates an HTTP client for the parsed engine address.
//
// A unix socket uses plain HTTP over the socket -- access control is the
// socket file's own and the request never reaches a network. Everything else
// is https: if an explicit CA is configured, only that CA is trusted (pinned
// mode), otherwise the system CA store is used. mTLS is used when client cert
// and key are provided.
func newHTTPClient(addr engineAddress, tlsCfg TLSConfig) (*http.Client, error) {
	transport := &http.Transport{
		DisableCompression: true,
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * clock.Second,
	}

	if addr.Unix {
		sockPath := addr.Socket.String()
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return nettransport.DialUnixSocket(ctx, sockPath)
		}
	} else {
		tc, err := tlsCfg.Build()
		if err != nil {
			return nil, fmt.Errorf("engine TLS: %w", err)
		}
		transport.TLSClientConfig = tc
	}

	var rt http.RoundTripper = transport
	if os.Getenv("STRIKE_AUDIT") != "" {
		rt = &auditTransport{inner: transport}
	}

	return &http.Client{Transport: rt}, nil
}

// apiBase returns the HTTP base URL for API requests. A unix socket uses
// http:// because the kernel routes by socket path and the scheme is
// irrelevant to it; that request never leaves the host. The network base is
// projected from the parsed address rather than assembled from pieces.
func apiBase(addr engineAddress) string {
	if addr.Unix {
		return "http://d" + apiPath
	}
	a := addr.Network
	p := primitive.NewAbsPath(apiPath)
	a.Path = &p
	return a.URL()
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
	line := fmt.Sprintf("AUDIT  %s %s -> %d (%s)",
		req.Method, req.URL.Path, status, duration.Round(clock.Millisecond))
	log.Print(sanitizeForLog(line))

	return resp, err
}

// sanitizeForLog replaces control characters -- which could forge audit log
// lines -- with '_'. The engine request path folds in lane-derived container
// and image names, so it passes through this guard before it reaches the log.
func sanitizeForLog(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteRune('_')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
