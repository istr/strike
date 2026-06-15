// Package resolver provides a per-step DNS allowlist resolver.
//
// Each lane step gets its own *Resolver instance, bound at
// construction to that step's name, allowlist, and synthesized
// address. The resolver is a pure allowlist gate: allowed names
// resolve to the step's loopback address (where the mediator
// listens); other names get NXDOMAIN; non-A/AAAA query types
// return NOTIMP. The resolver contacts no upstream -- the
// mediator performs real upstream resolution. See instruction 39
// and ADR-030.
//
// The resolver captures one QueryRecord per processed query for
// attestation; records are step-scoped because the resolver
// knows its step from construction.
//
// Architectural decisions: see docs/ROADMAP-ADR-028.md D19
// (per-step instance) and D20 (synthesizing server).
package resolver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/transport"
)

// Decision is the resolver's policy outcome for a single query.
type Decision string

// Decision constants for query outcomes.
const (
	DecisionAllowed Decision = "allowed"
	DecisionDenied  Decision = "denied"
	DecisionError   Decision = "error"
)

// QueryRecord captures one processed DNS query for attestation.
type QueryRecord struct {
	Time     clock.Time
	QName    string
	QType    string
	Err      string
	Decision Decision
	Answers  []netip.Addr
}

// ErrResolverClosed is returned by Serve after Close.
var ErrResolverClosed = errors.New("resolver: closed")

// Resolver is a per-step DNS server. It is a pure allowlist gate:
// allowed names resolve to synthAddr (the step's loopback address,
// where the mediator listens); other names get NXDOMAIN. The
// resolver contacts no upstream -- the mediator performs real
// upstream resolution. See instruction 39 / ADR-030.
type Resolver struct {
	synthAddr netip.Addr
	allowlist map[string]struct{}
	stepID    string
	records   []QueryRecord
	mu        sync.Mutex
	closed    bool
}

// New constructs a Resolver for one step.
//
//   - stepID identifies the step in QueryRecord and logs.
//   - allowlist enumerates the FQDNs the step is permitted to
//     resolve. Entries are normalized (lowercase, trailing dot
//     stripped) and de-duplicated; passing an empty allowlist is
//     valid and yields a resolver that denies every name.
//   - synthAddr is the step's loopback address. Allowed names
//     resolve to it (A record); the container then connects there,
//     reaching the step's mediator. Must be IPv4.
func New(stepID string, allowlist []transport.Host, synthAddr netip.Addr) (*Resolver, error) {
	if stepID == "" {
		return nil, errors.New("resolver: stepID must not be empty")
	}
	if !synthAddr.Is4() {
		return nil, fmt.Errorf("resolver: synthAddr must be IPv4, got %s", synthAddr)
	}

	set := make(map[string]struct{}, len(allowlist))
	for _, h := range allowlist {
		c, err := canonicalize(string(h))
		if err != nil {
			return nil, fmt.Errorf("resolver: invalid allowlist entry %q: %w", h, err)
		}
		set[c] = struct{}{}
	}

	return &Resolver{
		stepID:    stepID,
		allowlist: set,
		synthAddr: synthAddr,
	}, nil
}

// Serve handles DNS queries on udp and tcp until ctx is done.
// Caller owns the listeners; Serve does not close them. Returns
// the first non-nil error from either listener loop, or nil on
// clean ctx-cancellation.
func (r *Resolver) Serve(ctx context.Context, udp net.PacketConn, tcp net.Listener) error {
	if udp == nil || tcp == nil {
		return errors.New("resolver: udp and tcp listeners must both be non-nil")
	}

	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return ErrResolverClosed
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return r.udpLoop(gctx, udp) })
	g.Go(func() error { return r.tcpLoop(gctx, tcp) })
	err := g.Wait()
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

// Records returns a snapshot of all QueryRecords processed so far.
// Safe for concurrent use with active Serve.
func (r *Resolver) Records() []QueryRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]QueryRecord, len(r.records))
	copy(out, r.records)
	return out
}

// Close marks the resolver closed. Subsequent Serve returns
// ErrResolverClosed. Already-running Serve calls are not
// interrupted; cancel their context to stop them. Idempotent.
func (r *Resolver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

const pollInterval = 200 * clock.Millisecond

func (r *Resolver) udpLoop(ctx context.Context, udp net.PacketConn) error {
	buf := make([]byte, 512)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := udp.SetReadDeadline(clock.Wall().Add(pollInterval)); err != nil {
			return fmt.Errorf("resolver: udp set deadline: %w", err)
		}
		n, addr, err := udp.ReadFrom(buf)
		if isTimeoutErr(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("resolver: udp read: %w", err)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go r.handleUDPQuery(ctx, udp, addr, pkt)
	}
}

func (r *Resolver) tcpLoop(ctx context.Context, tcp net.Listener) error {
	type deadliner interface {
		SetDeadline(t clock.Time) error
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if d, ok := tcp.(deadliner); ok {
			if err := d.SetDeadline(clock.Wall().Add(pollInterval)); err != nil {
				return fmt.Errorf("resolver: tcp set deadline: %w", err)
			}
		}
		conn, err := tcp.Accept()
		if isTimeoutErr(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("resolver: tcp accept: %w", err)
		}
		go r.handleTCPConn(ctx, conn)
	}
}

func (r *Resolver) handleUDPQuery(ctx context.Context, udp net.PacketConn, addr net.Addr, pkt []byte) {
	resp := r.processQuery(ctx, pkt)
	if resp == nil {
		return
	}
	if _, err := udp.WriteTo(resp, addr); err != nil {
		log.Printf("WARN   resolver[%s]: udp write to %s: %v", r.stepID, addr, err)
	}
}

func (r *Resolver) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("WARN   resolver[%s]: tcp close: %v", r.stepID, err)
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if err := conn.SetReadDeadline(clock.Wall().Add(pollInterval)); err != nil {
			return
		}
		msg, err := readTCPMessage(conn)
		if isTimeoutErr(err) {
			continue
		}
		if err != nil {
			return // EOF or real error; just close
		}
		resp := r.processQuery(ctx, msg)
		if resp == nil {
			return
		}
		if err := writeTCPMessage(conn, resp); err != nil {
			log.Printf("WARN   resolver[%s]: tcp write: %v", r.stepID, err)
			return
		}
	}
}

func (r *Resolver) appendRecord(rec QueryRecord) {
	r.mu.Lock()
	r.records = append(r.records, rec)
	r.mu.Unlock()
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func canonicalize(name string) (string, error) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if n == "" {
		return "", errors.New("empty name")
	}
	// Strip any port suffix (Host is a typed string that may
	// include :port; allowlist matching is on hostname only).
	if i := strings.LastIndex(n, ":"); i >= 0 {
		n = n[:i]
	}
	if n == "" {
		return "", errors.New("empty name after port strip")
	}
	return n, nil
}
