package transport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
)

// bsiTLS12CipherSuites is the set of TLS 1.2 cipher suites strike
// offers to external peers: the AEAD/ECDHE (Perfect Forward Secrecy)
// suites recommended by BSI TR-02102-2 that Go's crypto/tls supports.
// CBC suites (BSI-recommended only with Encrypt-then-MAC; Lucky-13 /
// padding-oracle surface), AES-CCM (not implemented by Go for TLS
// 1.2), and ChaCha20-Poly1305 (not on the BSI list) are deliberately
// excluded. This governs the TLS 1.2 path only; Go fixes the TLS 1.3
// suite set and ignores CipherSuites for it.
var bsiTLS12CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// ConnectionIdentity captures the verified peer identity from
// a TLS handshake. Every TLS connection strike establishes
// (DoT resolver, TLS mediator upstream, controller direct
// calls) records this; the captured material flows into deploy
// attestations and audit records.
type ConnectionIdentity struct {
	// LeafFingerprint is the SHA-256 fingerprint of the leaf
	// certificate, formatted as "sha256:<64 lowercase hex>".
	// Empty when PeerCertificates is empty.
	LeafFingerprint primitive.Digest

	// ServerName is the SNI value the client sent during the
	// handshake. Empty for IP-literal addresses (per RFC 6066,
	// SNI must not be an IP literal).
	ServerName string

	// PeerAddress is the verified identity and port the connection
	// was established to, as recorded by DialResolved.
	PeerAddress endpoint.Address

	// PeerCertificates is the certificate chain presented by
	// the peer during the handshake. Index 0 is the leaf cert.
	// Empty if no certs were presented (which would have caused
	// verification to fail; this field is for post-success
	// inspection).
	PeerCertificates []*x509.Certificate

	// TLSVersion is the negotiated TLS version. External-peer hops
	// (DoT resolver, mediator upstream) floor at TLS 1.2 and prefer
	// 1.3; controlled hops (engine, mediator client) remain 1.3.
	// See the peer-TLS-floor ADR.
	TLSVersion uint16

	// CipherSuite is the negotiated cipher suite. TLS 1.3 has
	// a fixed set of AEAD suites; the field records which one.
	CipherSuite uint16
}

// VerifiedConn is a TLS connection whose peer has been verified
// against a declared trust anchor. Identity is captured at
// handshake time and is available via Identity(); the underlying
// verified connection is available via Conn().
type VerifiedConn struct {
	conn     *tls.Conn
	identity ConnectionIdentity
}

// Identity returns the connection identity captured at handshake.
func (c *VerifiedConn) Identity() ConnectionIdentity {
	return c.identity
}

// Conn returns the underlying verified TLS connection.
func (c *VerifiedConn) Conn() net.Conn {
	return c.conn
}

// BuildTLSConfig produces a *tls.Config that verifies a peer
// against the supplied endpoint.Trust. Minimum TLS 1.2 (external peers
// such as public registries are not always 1.3-capable; see the
// peer-TLS-floor ADR), with the TLS 1.2 path restricted to the BSI
// TR-02102-2 AEAD/PFS cipher suites; TLS 1.3 is preferred and used
// whenever the peer supports it. No caller-facing options; the
// returned config is wired for exactly the trust mode declared.
//
// For endpoint.Fingerprint: standard chain verification is bypassed
// (InsecureSkipVerify=true) and replaced with a SHA-256
// fingerprint match on the leaf certificate. This is the only
// path in strike code that sets InsecureSkipVerify=true; the
// VerifyPeerCertificate callback is what actually enforces
// trust.
//
// For endpoint.CABundle: the bundle file is read from disk and
// installed as RootCAs. Standard chain verification applies.
func BuildTLSConfig(trust endpoint.Trust) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: bsiTLS12CipherSuites,
	}
	switch t := trust.(type) {
	case endpoint.Fingerprint:
		config.InsecureSkipVerify = true
		config.VerifyPeerCertificate = makeFingerprintVerifier(t.Fingerprint)
		config.VerifyConnection = makeConnectionFingerprintVerifier(t.Fingerprint)
	case endpoint.CABundle:
		pool, err := loadCABundle(t.Path)
		if err != nil {
			return nil, err
		}
		config.RootCAs = pool
	default:
		return nil, fmt.Errorf("transport: unknown trust type: %T", trust)
	}
	return config, nil
}

// DialResolved opens a verified TLS connection to an already-resolved
// address and verifies the presented certificate against serverName.
//
// Routing and identity are two parameters, not one. A name cannot be
// passed as the destination: the parameter type is what enforces that,
// so no DNS-based routing decision can be taken here and none can be
// taken by the standard library on this path either. Callers that hold
// a name resolve it through the lane's declared resolver first --
// Dialer.DialPeer does exactly that and is the usual entry point.
//
// serverName is required. It is sent as the SNI extension when it is a
// hostname and suppressed when it is an address literal (RFC 6066), and
// it is the reference identifier the certificate is verified against in
// both cases. An empty serverName is an error rather than a silent
// downgrade to an unverified name.
//
// The context governs the dial timeout; pass a context with a deadline
// if a timeout is desired.
func DialResolved(ctx context.Context, dst netip.AddrPort, serverName primitive.Host, trust endpoint.Trust) (*VerifiedConn, error) {
	if !dst.IsValid() || dst.Port() == 0 {
		return nil, errors.New("transport: dial requires a resolved address and port")
	}
	if serverName == "" {
		return nil, errors.New("transport: dial requires a verification name")
	}
	config, err := BuildTLSConfig(trust)
	if err != nil {
		return nil, err
	}
	config.ServerName = serverName.String()

	raw, err := dialTCP(ctx, dst)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, config)
	if hsErr := conn.HandshakeContext(ctx); hsErr != nil {
		closer.Warn(raw, "transport: raw conn (handshake error)")
		return nil, fmt.Errorf("transport: handshake %s: %w", serverName, hsErr)
	}

	port := primitive.Port(dst.Port())
	addr := endpoint.Address{Host: serverName, Port: &port}
	identity := CaptureIdentity(conn.ConnectionState(), addr)
	return &VerifiedConn{conn: conn, identity: identity}, nil
}

// makeFingerprintVerifier returns a VerifyPeerCertificate
// callback that succeeds iff the leaf certificate's SHA-256
// fingerprint matches the expected "sha256:<hex>" string.
func makeFingerprintVerifier(expected primitive.Digest) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("transport: no peer certificate presented")
		}
		sum := sha256.Sum256(rawCerts[0])
		got := primitive.DigestFromHex(hex.EncodeToString(sum[:]))
		if got != expected {
			return fmt.Errorf("transport: peer certificate fingerprint mismatch: got %s, want %s",
				got, expected)
		}
		return nil
	}
}

// makeConnectionFingerprintVerifier returns a VerifyConnection
// callback that re-checks the leaf fingerprint on resumed
// sessions. VerifyPeerCertificate is not called for resumed
// connections (the raw certs are not re-sent); VerifyConnection
// receives the cached peer certificates and closes the gap.
func makeConnectionFingerprintVerifier(expected primitive.Digest) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("transport: no peer certificate in connection state")
		}
		sum := sha256.Sum256(state.PeerCertificates[0].Raw)
		got := primitive.DigestFromHex(hex.EncodeToString(sum[:]))
		if got != expected {
			return fmt.Errorf("transport: peer certificate fingerprint mismatch (resumed): got %s, want %s",
				got, expected)
		}
		return nil
	}
}

// loadCABundle reads a PEM-encoded CA bundle file and returns
// it as a CertPool. The path is treated as an operator-supplied
// filesystem location; lane schema validation has already
// confirmed it is canonical absolute, but it is still variable
// from gosec's perspective.
func loadCABundle(path primitive.AbsPath) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(filepath.Clean(path.String()))
	if err != nil {
		return nil, fmt.Errorf("transport: read CA bundle %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("transport: CA bundle %q contains no certificates", path)
	}
	return pool, nil
}

// CaptureIdentity extracts the connection identity from a
// completed TLS handshake. The addr parameter populates
// PeerAddress (typically host:port or the SNI, depending on
// the caller's context).
func CaptureIdentity(state tls.ConnectionState, addr endpoint.Address) ConnectionIdentity {
	id := ConnectionIdentity{
		PeerCertificates: state.PeerCertificates,
		TLSVersion:       state.Version,
		CipherSuite:      state.CipherSuite,
		ServerName:       state.ServerName,
		PeerAddress:      addr,
	}
	if len(state.PeerCertificates) > 0 {
		sum := sha256.Sum256(state.PeerCertificates[0].Raw)
		id.LeafFingerprint = primitive.DigestFromHex(hex.EncodeToString(sum[:]))
	}
	return id
}

// DialUnixSocket opens a validated connection to a Unix-domain
// socket. The path is resolved via EvalSymlinks, checked to be
// a socket (ModeSocket), and verified to be owned by the
// current user (uid match). Returns a *net.UnixConn connected
// to the resolved path.
//
// Error strings intentionally omit the path to avoid leaking
// host filesystem layout in logs or error chains.
func DialUnixSocket(ctx context.Context, path string) (*net.UnixConn, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("transport: resolve unix socket: %w", err)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return nil, fmt.Errorf("transport: stat unix socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil, errors.New("transport: path is not a unix socket")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("transport: cannot determine socket owner")
	}
	if int64(st.Uid) != int64(os.Getuid()) {
		return nil, errors.New("transport: unix socket owner does not match current user")
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", resolved)
	if err != nil {
		return nil, fmt.Errorf("transport: dial unix socket: %w", err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		closer.Warn(conn, "transport: non-unix conn cleanup")
		return nil, errors.New("transport: dialer returned non-unix connection")
	}
	return uc, nil
}

// dialTCP opens a TCP connection to dst, a resolved IP address and
// port. A name cannot be passed: callers resolve through the
// capsule's DoT resolver first, so no DNS-based routing happens
// outside the resolver allowlist. The parameter type is what
// enforces that, so there is no hostname case to reject here.
// DialResolved is the only caller and rejects an invalid address or a
// zero port before calling, so dst is already known good here.
func dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return nil, fmt.Errorf("transport: dial tcp: %w", err)
	}
	return conn, nil
}
