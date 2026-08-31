// Package mediator provides a per-step TLS proxy that terminates
// container-side TLS using an ephemeral CA and re-establishes
// upstream TLS against the lane-declared trust anchor.
//
// Each lane step gets its own *Mediator instance, bound at
// construction to that step's peer-trust map and its ephemeral
// CA. The mediator captures one ConnectionRecord per attempted
// connection for attestation.
//
// Architectural decisions: see docs/ADR-028-step-container-egress-mediation.md,
// "Component 2: Controller-side mediation" (per-step mediator instance,
// SNI-preserving upstream dial / split TLS).
package mediator

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/transport"
)

// PeerTrust ties a peer SNI to its TLS trust anchor.
type PeerTrust struct {
	Trust   endpoint.Trust
	Address endpoint.Address
}

// defaultUpstreamPort is the port the mediator dials when a declared peer
// carries no explicit port.
const defaultUpstreamPort uint16 = 443

// peerEntry is one declared peer in the form the connection path needs it:
// the trust anchor, the canonical form of the declared host, and the declared
// port -- defaulted so it is never absent -- in the type the dialer takes.
// The defaulting, the canonicalization and the conversion all happen once, at
// construction, so a connection carries no default handling of its own and
// takes the name it resolves and records from the lane declaration rather
// than from the container's SNI string.
type peerEntry struct {
	trust endpoint.Trust
	name  primitive.Host
	port  uint16
}

// Decision is the mediator's policy outcome for a connection.
type Decision string

// Decision constants for connection outcomes.
const (
	DecisionAllowed Decision = "allowed"
	DecisionDenied  Decision = "denied"
	DecisionError   Decision = "error"
)

// ConnectionRecord captures one mediated connection attempt for
// attestation.
type ConnectionRecord struct {
	Time     clock.Time
	Upstream *transport.ConnectionIdentity // nil unless DecisionAllowed
	SNI      string                        // canonicalized
	Err      string                        // populated when DecisionError
	Decision Decision
	Resolved []netip.Addr // upstream IPs from the DoT lookup; set on DecisionAllowed
}

// ErrMediatorClosed is returned by Serve after Close.
var ErrMediatorClosed = errors.New("mediator: closed")

// Mediator is a per-step TLS proxy.
type Mediator struct {
	peers   map[string]peerEntry // canonical SNI -> peer (trust, canonical name, dial port)
	ca      *transport.EphemeralCA
	dialer  *transport.Dialer
	stepID  string
	records []ConnectionRecord
	mu      sync.Mutex
	closed  bool
}

// New constructs a Mediator for one step.
//
//   - stepID identifies the step in ConnectionRecord and logs.
//   - peers enumerates the (SNI, trust) pairs the step may reach.
//     Entries are canonicalized (lowercase host, trailing dot
//     stripped); a peer that declares no port is dialed on
//     defaultUpstreamPort. An empty peers slice yields a mediator
//     that denies every SNI.
//   - ca is the ephemeral CA whose GetCertificate is wrapped with
//     the SNI-allowlist gate. May be shared across mediators in
//     the same lane run.
//   - dialer resolves a declared peer through the lane's allowlisted DoT
//     resolver and dials it against its declared trust anchor. Must be
//     non-nil.
func New(stepID string, peers []PeerTrust, ca *transport.EphemeralCA, dialer *transport.Dialer) (*Mediator, error) {
	if stepID == "" {
		return nil, errors.New("mediator: stepID must not be empty")
	}
	if ca == nil {
		return nil, errors.New("mediator: ca must not be nil")
	}
	if dialer == nil {
		return nil, errors.New("mediator: dialer must not be nil")
	}

	peerMap := make(map[string]peerEntry, len(peers))
	for _, p := range peers {
		c, err := canonicalize(p.Address.Host.String())
		if err != nil {
			return nil, fmt.Errorf("mediator: invalid peer host %q: %w", p.Address.Host, err)
		}
		if _, dup := peerMap[c]; dup {
			return nil, fmt.Errorf("mediator: duplicate peer %q", c)
		}
		n := primitive.Port(defaultUpstreamPort)
		if p.Address.Port != nil {
			n = *p.Address.Port
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("mediator: peer %q port %d out of range 1..65535", c, n)
		}
		peerMap[c] = peerEntry{trust: p.Trust, name: primitive.Host(c), port: uint16(n)}
	}

	return &Mediator{
		stepID: stepID,
		peers:  peerMap,
		ca:     ca,
		dialer: dialer,
	}, nil
}

// Serve accepts TCP connections on listener until ctx is done.
// Caller owns the listener; Serve does not close it. Returns the
// first non-nil error from the accept loop, or nil on clean
// ctx cancellation.
func (m *Mediator) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("mediator: listener must not be nil")
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return ErrMediatorClosed
	}
	return m.acceptLoop(ctx, listener)
}

// Records returns a snapshot of all ConnectionRecords. Safe for
// concurrent use with active Serve.
func (m *Mediator) Records() []ConnectionRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ConnectionRecord, len(m.records))
	copy(out, m.records)
	return out
}

// Close marks the mediator closed. Subsequent Serve returns
// ErrMediatorClosed. It does not stop a running Serve: cancelling the
// Serve context does that, and cancellation also closes every
// in-flight proxied connection. Idempotent.
func (m *Mediator) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

const (
	acceptPollInterval = 200 * clock.Millisecond
	handshakeTimeout   = 10 * clock.Second
)

func (m *Mediator) acceptLoop(ctx context.Context, listener net.Listener) error {
	type deadliner interface{ SetDeadline(t clock.Time) error }
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		for {
			if err := gctx.Err(); err != nil {
				return err
			}
			if d, ok := listener.(deadliner); ok {
				if err := d.SetDeadline(clock.Wall().Add(acceptPollInterval)); err != nil {
					return fmt.Errorf("mediator: set deadline: %w", err)
				}
			}
			conn, acceptErr := listener.Accept()
			if isTimeoutErr(acceptErr) {
				continue
			}
			if acceptErr != nil {
				return fmt.Errorf("mediator: accept: %w", acceptErr)
			}
			g.Go(func() error {
				m.handleConn(gctx, conn)
				return nil
			})
		}
	})
	err := g.Wait()
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func (m *Mediator) handleConn(ctx context.Context, raw net.Conn) {
	defer func() {
		if err := raw.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("WARN   mediator[%s]: raw conn close: %v", m.stepID, err)
		}
	}()

	tlsConfig := &tls.Config{
		GetCertificate: m.getCertificate,
		MinVersion:     tls.VersionTLS13,
	}
	clientSide := tls.Server(raw, tlsConfig)
	defer closer.Warn(clientSide, fmt.Sprintf("mediator[%s]: client tls", m.stepID))

	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err := clientSide.HandshakeContext(handshakeCtx); err != nil {
		// getCertificate has already recorded a denial if that
		// was the cause. Anything else (TLS protocol error,
		// version mismatch) is a generic handshake failure that
		// does not warrant a record (no SNI was successfully
		// received).
		return
	}

	sni := canonicalizeOrEmpty(clientSide.ConnectionState().ServerName)
	pt, ok := m.peers[sni]
	if !ok {
		// Should not reach here: getCertificate would have
		// rejected. Defensive check.
		m.appendRecord(ConnectionRecord{
			Time: clock.Wall(), SNI: sni, Decision: DecisionDenied,
		})
		return
	}

	upstreamConn, identity, resolved, err := m.dialUpstream(handshakeCtx, sni, pt)
	if err != nil {
		log.Printf("WARN   mediator[%s]: upstream %s failed: %v", m.stepID, sni, err)
		m.appendRecord(ConnectionRecord{
			Time: clock.Wall(), SNI: sni, Decision: DecisionError, Err: err.Error(),
		})
		return
	}
	defer closer.Warn(upstreamConn, fmt.Sprintf("mediator[%s]: upstream %s", m.stepID, sni))

	m.appendRecord(ConnectionRecord{
		Time:     clock.Wall(),
		SNI:      sni,
		Decision: DecisionAllowed,
		Upstream: identity,
		Resolved: resolved,
	})

	if err := proxyBidirectional(ctx, clientSide, upstreamConn); err != nil {
		log.Printf("WARN   mediator[%s]: proxy %s: %v", m.stepID, sni, err)
	}
}

func (m *Mediator) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := canonicalizeOrEmpty(hello.ServerName)
	if sni == "" {
		m.appendRecord(ConnectionRecord{
			Time: clock.Wall(), SNI: "", Decision: DecisionDenied,
			Err: "empty SNI",
		})
		return nil, fmt.Errorf("mediator: empty SNI")
	}
	if _, ok := m.peers[sni]; !ok {
		m.appendRecord(ConnectionRecord{
			Time: clock.Wall(), SNI: sni, Decision: DecisionDenied,
		})
		return nil, fmt.Errorf("mediator: SNI %q not in peer allowlist", sni)
	}
	return m.ca.GetCertificate(hello)
}

func (m *Mediator) dialUpstream(ctx context.Context, sni string, pe peerEntry) (*tls.Conn, *transport.ConnectionIdentity, []netip.Addr, error) {
	// The name resolved and verified here is the matched peer's declared
	// host, not the container-supplied SNI string: a peer-map hit proves the
	// two canonicalize to the same value, and the declaration is the lane's
	// own program state. The SNI the container sent is forwarded unchanged
	// (ADR-028, SNI-preserving upstream dial) and recorded as SNI.
	addrs, err := m.dialer.LookupHost(ctx, pe.name.String())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("upstream lookup %q: %w", sni, err)
	}
	if len(addrs) == 0 {
		return nil, nil, nil, fmt.Errorf("upstream lookup %q: no addresses", sni)
	}

	dst := netip.AddrPortFrom(addrs[0], pe.port)
	vc, err := transport.DialResolved(ctx, dst, pe.name, pe.trust)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("upstream dial %s: %w", dst, err)
	}
	upstream, ok := vc.Conn().(*tls.Conn)
	if !ok {
		closer.Warn(vc.Conn(), fmt.Sprintf("mediator: upstream %s (non-TLS conn)", sni))
		return nil, nil, nil, fmt.Errorf("upstream %s: dial returned a non-TLS connection", sni)
	}

	identity := vc.Identity()
	return upstream, &identity, addrs, nil
}

func (m *Mediator) appendRecord(rec ConnectionRecord) {
	m.mu.Lock()
	m.records = append(m.records, rec)
	m.mu.Unlock()
}

// proxyBidirectional copies between the two connections until both
// directions have drained or ctx is done. Cancellation closes both
// connections, which unblocks the copies: a join can only wait on a
// worker that cancellation can stop (ADR-052 D2).
func proxyBidirectional(ctx context.Context, a, b *tls.Conn) error {
	stop := context.AfterFunc(ctx, func() {
		closer.Warn(a, "mediator: proxy client (cancelled)")
		closer.Warn(b, "mediator: proxy upstream (cancelled)")
	})
	defer stop()

	var g errgroup.Group
	g.Go(func() error {
		_, copyErr := io.Copy(b, a)
		if cwErr := b.CloseWrite(); cwErr != nil && copyErr == nil {
			copyErr = cwErr
		}
		return copyErr
	})
	g.Go(func() error {
		_, copyErr := io.Copy(a, b)
		if cwErr := a.CloseWrite(); cwErr != nil && copyErr == nil {
			copyErr = cwErr
		}
		return copyErr
	})
	err := g.Wait()
	if err != nil && (errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)) {
		return nil
	}
	if ctx.Err() != nil {
		// The copies were interrupted on purpose. A TLS conn does not
		// always report a closed transport as net.ErrClosed, so the
		// filter above cannot be relied on to catch this case.
		return nil
	}
	return err
}

func canonicalize(name string) (string, error) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if n == "" {
		return "", errors.New("empty name")
	}
	return n, nil
}

func canonicalizeOrEmpty(name string) string {
	c, err := canonicalize(name)
	if err != nil {
		return ""
	}
	return c
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
