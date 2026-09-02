package transport_test

import (
	"context"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/testutil"
)

// TestDialerProbe_HarnessDoT_INTEGRATION exercises Dialer.Probe
// against the local harness DoT resolver at 127.0.0.1:8853. The
// resolver serves a synthetic root zone with no forwarder, so the
// probe's NS . query is answered with no egress at all, and its
// trust anchor is the checked-out pki/resolver.crt.
//
// The harness is a prerequisite: the test runs by default and
// fails fast when it is down; set STRIKE_INTEGRATION=0 to skip.
func TestDialerProbe_HarnessDoT_INTEGRATION(t *testing.T) {
	engine := testutil.RequireEngine(t)
	harness := testutil.HarnessDir(t)
	testutil.RequireHarness(t, engine, harness)
	ctx, cancel := context.WithTimeout(context.Background(), 10*clock.Second)
	defer cancel()
	dialer, err := testutil.HarnessDialer(harness)
	if err != nil {
		t.Fatalf("HarnessDialer: %v", err)
	}
	if _, err := dialer.Probe(ctx); err != nil {
		t.Fatalf("Probe: %v", err)
	}
}

// TestDialerLookupHost_HarnessNames_INTEGRATION pins the harness root zone
// against the names the control plane resolves through it. Every endpoint the
// control plane dials by name is resolved by the declared resolver, so a zone
// that answers for the registry but not for the signing endpoints leaves those
// unreachable while every other integration test still passes -- a failure that
// otherwise surfaces only in the slowest tests in the suite.
//
// The harness is a prerequisite: the test runs by default and fails fast when
// it is down; set STRIKE_INTEGRATION=0 to skip.
func TestDialerLookupHost_HarnessNames_INTEGRATION(t *testing.T) {
	engine := testutil.RequireEngine(t)
	harness := testutil.HarnessDir(t)
	testutil.RequireHarness(t, engine, harness)
	dialer, err := testutil.HarnessDialer(harness)
	if err != nil {
		t.Fatalf("HarnessDialer: %v", err)
	}
	for _, name := range []string{
		"registry.127.0.0.1.sslip.io",
		"fulcio.127.0.0.1.sslip.io",
		"rekor.127.0.0.1.sslip.io",
		"tsa.127.0.0.1.sslip.io",
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*clock.Second)
			defer cancel()
			addrs, err := dialer.LookupHost(ctx, name)
			if err != nil {
				t.Fatalf("LookupHost %s: %v", name, err)
			}
			if len(addrs) == 0 {
				t.Fatalf("LookupHost %s returned no addresses", name)
			}
		})
	}
}
