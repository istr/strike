package transport_test

import (
	"context"
	"crypto/tls"
	"os"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/transport"
)

// TestDialVerified_CloudflareDoT_INTEGRATION connects to
// Cloudflare's public DoT endpoint on 1.1.1.1:853 to verify
// the primitive works against a real-world peer. The expected
// fingerprint is read from an environment variable
// (STRIKE_CLOUDFLARE_DOT_FINGERPRINT) to avoid hard-coding a
// value that rotates; obtain via openssl s_client (see
// docs/DNS-RESOLVER-CONFIGURATION.md).
//
// The test fails fast if the env variable is unset; the
// operator running integration tests is expected to set it.
func TestDialVerified_CloudflareDoT_INTEGRATION(t *testing.T) {
	fingerprint := os.Getenv("STRIKE_CLOUDFLARE_DOT_FINGERPRINT")
	if fingerprint == "" {
		t.Skip("STRIKE_CLOUDFLARE_DOT_FINGERPRINT not set; skipping")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*clock.Second)
	defer cancel()
	trust := endpoint.Fingerprint{
		Type:        "certFingerprint",
		Fingerprint: fingerprint,
	}
	conn, err := transport.DialVerified(ctx, "1.1.1.1:853", trust)
	if err != nil {
		t.Fatalf("DialVerified: %v", err)
	}
	defer closer.Warn(conn, "cloudflare DoT conn")
	id := conn.Identity()
	if id.TLSVersion != tls.VersionTLS13 {
		t.Errorf("TLS version = 0x%x, want TLS 1.3", id.TLSVersion)
	}
	if id.LeafFingerprint != fingerprint {
		t.Errorf("LeafFingerprint = %q, want %q", id.LeafFingerprint, fingerprint)
	}
}
