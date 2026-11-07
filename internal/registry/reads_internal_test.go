package registry

import (
	"context"
	"strings"
	"testing"
)

// TestReadsDialTransportRejects pins the dial layer under the read policy: a
// dial to an authority outside the registry and its storages, and any
// plaintext dial, are refused before a socket opens.
func TestReadsDialTransportRejects(t *testing.T) {
	rt := (&Reads{}).dialTransport("images.example.com", nil)
	if _, err := rt.DialTLSContext(context.Background(), "tcp", "elsewhere.example.com:443"); err == nil || !strings.Contains(err.Error(), "outside registry images.example.com") {
		t.Errorf("TLS dial error = %v, want a rejection outside the registry", err)
	}
	if _, err := rt.DialContext(context.Background(), "tcp", "images.example.com:80"); err == nil || !strings.Contains(err.Error(), "plaintext dial") {
		t.Errorf("plaintext dial error = %v, want a rejection", err)
	}
}
