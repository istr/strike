package transport_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

// TestProbeResolver_HarnessDoT_INTEGRATION exercises ProbeResolver
// against the local harness DoT resolver at 127.0.0.1:8853. The
// resolver serves a synthetic root zone with no forwarder, so the
// probe's NS . query is answered with no egress at all, and its
// trust anchor is the checked-out pki/resolver.crt.
//
// The harness is a prerequisite: the test runs by default and
// fails fast when it is down; set STRIKE_INTEGRATION=0 to skip.
func TestProbeResolver_HarnessDoT_INTEGRATION(t *testing.T) {
	engine := testutil.RequireEngine(t)
	harness := testutil.HarnessDir(t)
	testutil.RequireHarness(t, engine, harness)
	ctx, cancel := context.WithTimeout(context.Background(), 10*clock.Second)
	defer cancel()
	decl := endpoint.TLS{
		Type:    "https",
		Address: endpoint.MustParseAuthority("127.0.0.1:8853"),
		Trust: endpoint.CABundle{
			Type: "caBundle",
			Path: primitive.AbsPath(filepath.Join(harness, "pki", "resolver.crt")),
		},
	}
	if _, err := transport.ProbeResolver(ctx, decl); err != nil {
		t.Fatalf("ProbeResolver: %v", err)
	}
}
