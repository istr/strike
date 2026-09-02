package deploy

import (
	"net/netip"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/transport"
)

// TestEngineRecords covers the projection of the engine identity into the
// sealed connection record and the informational metadata. The projection is a
// pure function of Deployer.EngineID, so it is exercised directly rather than
// through a deploy.
func TestEngineRecords(t *testing.T) {
	tests := []struct {
		id    *container.EngineIdentity
		check func(t *testing.T, conn endpoint.Engine, meta *EngineMetadata)
		name  string
	}{
		{
			name: "nil identity yields no records",
			id:   nil,
			check: func(t *testing.T, conn endpoint.Engine, meta *EngineMetadata) {
				if conn != nil {
					t.Errorf("connection = %v, want nil", conn)
				}
				if meta != nil {
					t.Errorf("metadata = %v, want nil", meta)
				}
			},
		},
		{
			name: "mtls with runtime",
			id: &container.EngineIdentity{
				Connection: container.ConnectionInfo{
					Type:                  "mtls",
					CATrustType:           "pinned",
					ServerCertFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					ClientCertFingerprint: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				},
				Runtime: &container.RuntimeInfo{Version: "5.2.1", Rootless: true},
			},
			check: func(t *testing.T, conn endpoint.Engine, meta *EngineMetadata) {
				mtls, ok := conn.(endpoint.EngineMTLS)
				if !ok {
					t.Fatalf("connection type = %T, want endpoint.EngineMTLS", conn)
				}
				if mtls.ServerCertFingerprint != "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
					t.Errorf("ServerCertFingerprint = %q", mtls.ServerCertFingerprint)
				}
				if mtls.ClientCertFingerprint != "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
					t.Errorf("ClientCertFingerprint = %q", mtls.ClientCertFingerprint)
				}
				if meta == nil {
					t.Fatal("metadata = nil, want non-nil")
				}
				if meta.Version != "5.2.1" {
					t.Errorf("Version = %q, want 5.2.1", meta.Version)
				}
				if meta.Rootless == nil || !*meta.Rootless {
					t.Error("Rootless = nil or false, want true")
				}
			},
		},
		{
			name: "unix without runtime",
			id: &container.EngineIdentity{
				Connection: container.ConnectionInfo{Type: "unix"},
			},
			check: func(t *testing.T, conn endpoint.Engine, meta *EngineMetadata) {
				if conn == nil {
					t.Fatal("connection = nil, want non-nil")
				}
				if conn.ConnectionType() != "unix" {
					t.Errorf("ConnectionType = %q, want unix", conn.ConnectionType())
				}
				if meta == nil {
					t.Fatal("metadata = nil, want non-nil")
				}
				if meta.Rootless != nil {
					t.Error("Rootless is set, want nil when Runtime is nil")
				}
				if meta.Version != "" {
					t.Errorf("Version = %q, want empty", meta.Version)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &Deployer{EngineID: tc.id}
			conn, meta := d.engineRecords()
			tc.check(t, conn, meta)
		})
	}
}

// TestResolverRecord covers the projection of the observed resolver identity
// into the sealed record. The declared endpoint is sealed via the lane digest,
// not duplicated here, so only the observed half is projected.
func TestResolverRecord(t *testing.T) {
	observed := transport.ConnectionIdentity{
		LeafFingerprint: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		TLSVersion:      0x0304,
		CipherSuite:     0x1301,
		PeerAddress:     endpoint.MustParseAuthority("one.one.one.one:853"),
		DialedAddr:      netip.MustParseAddrPort("1.1.1.1:853"),
	}
	d := &Deployer{Resolver: ResolverProbe{Observed: observed}}

	rec := d.resolverRecord()
	if rec.Host != "one.one.one.one:853" {
		t.Errorf("Host = %q, want one.one.one.one:853", rec.Host)
	}
	if rec.DialedIP != "1.1.1.1" {
		t.Errorf("DialedIP = %q, want 1.1.1.1", rec.DialedIP)
	}
	if rec.ServerCertFingerprint != observed.LeafFingerprint.String() {
		t.Errorf("ServerCertFingerprint = %q, want %q", rec.ServerCertFingerprint, observed.LeafFingerprint)
	}
	if rec.TLSVersion != "TLS 1.3" {
		t.Errorf("TLSVersion = %q, want TLS 1.3", rec.TLSVersion)
	}
	if rec.CipherSuite == "" {
		t.Error("CipherSuite is empty, want the resolved suite name")
	}
}
