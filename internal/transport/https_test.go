package transport_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/istr/strike/internal/transport"
)

// schemeRecorder answers every request in-process and records the scheme it
// arrived with.
type schemeRecorder struct {
	scheme string
}

func (s *schemeRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	s.scheme = r.URL.Scheme
	return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Request: r}, nil
}

// TestHTTPSOnly pins that a request leaves on https whatever scheme it was
// built with, and that the caller's request keeps its own scheme.
func TestHTTPSOnly(t *testing.T) {
	rec := &schemeRecorder{}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://registry.example.com/v2/", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := transport.HTTPSOnly(rec).RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Errorf("close body: %v", closeErr)
	}
	if rec.scheme != "https" {
		t.Errorf("scheme at the inner round tripper = %q, want https", rec.scheme)
	}
	if req.URL.Scheme != "http" {
		t.Errorf("caller's request scheme = %q, want it unchanged as http", req.URL.Scheme)
	}
}
