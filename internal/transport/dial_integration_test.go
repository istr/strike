package transport_test

import (
	"context"
	"crypto/tls"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

// TestDialResolved_HarnessDoT_INTEGRATION connects to the local
// harness DoT resolver on 127.0.0.1:8853 to verify the primitive
// works against a real DNS-over-TLS server. The resolver
// terminates TLS itself under pki/resolver.crt -- a self-signed
// certificate generated once beside the other harness keys and
// reused across restarts -- so the trust anchor is a checked-out
// file rather than a value an operator refreshes by hand. The
// verification name is an IP literal, so no SNI is sent and the
// certificate is accepted on its IP entry.
//
// The harness is a prerequisite: the test runs by default and
// fails fast when it is down; set STRIKE_INTEGRATION=0 to skip.
func TestDialResolved_HarnessDoT_INTEGRATION(t *testing.T) {
	engine := testutil.RequireEngine(t)
	harness := testutil.HarnessDir(t)
	testutil.RequireHarness(t, engine, harness)
	trust := endpoint.CABundle{
		Type: "caBundle",
		Path: primitive.AbsPath(filepath.Join(harness, "pki", "resolver.crt")),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*clock.Second)
	defer cancel()
	conn, err := transport.DialResolved(ctx, netip.MustParseAddrPort("127.0.0.1:8853"), "127.0.0.1", trust)
	if err != nil {
		t.Fatalf("DialResolved: %v", err)
	}
	defer closer.Warn(conn.Conn(), "harness DoT conn")
	id := conn.Identity()
	if id.TLSVersion != tls.VersionTLS13 {
		t.Errorf("TLS version = 0x%x, want TLS 1.3", id.TLSVersion)
	}
	if id.LeafFingerprint == "" {
		t.Error("LeafFingerprint is empty")
	}
}
