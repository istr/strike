package transport_test

import (
	"context"
	"os"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/transport"
)

// TestProbeResolver_CloudflareDoT_INTEGRATION exercises
// ProbeResolver against Cloudflare's public DoT endpoint at
// 1.1.1.1:853. The expected fingerprint is read from
// STRIKE_CLOUDFLARE_DOT_FINGERPRINT to avoid hard-coding a
// rotating value; obtain via openssl s_client (see
// docs/DNS-RESOLVER-CONFIGURATION.md).
//
// Test fails fast if the env variable is unset; the operator
// running integration tests is expected to set it.
func TestProbeResolver_CloudflareDoT_INTEGRATION(t *testing.T) {
	fingerprint := primitive.Digest(os.Getenv("STRIKE_CLOUDFLARE_DOT_FINGERPRINT"))
	if fingerprint == "" {
		t.Skip("STRIKE_CLOUDFLARE_DOT_FINGERPRINT not set; skipping")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*clock.Second)
	defer cancel()
	decl := endpoint.TLS{
		Type:    "https",
		Address: endpoint.MustParseAuthority("1.1.1.1:853"),
		Trust: endpoint.Fingerprint{
			Type:        "certFingerprint",
			Fingerprint: fingerprint,
		},
	}
	if _, err := transport.ProbeResolver(ctx, decl); err != nil {
		t.Fatalf("ProbeResolver: %v", err)
	}
}
