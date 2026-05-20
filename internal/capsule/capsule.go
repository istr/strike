// Package capsule aggregates the per-step network components
// produced by Phase 2: the allowlist DNS resolver, the TLS
// mediator, and the pasta egress filter argument list. A
// NetworkCapsule represents one step's bundled lifecycle.
//
// Architectural decisions: see docs/ROADMAP-ADR-028.md D25
// (NetworkCapsule aggregate) and D26 (HTTPS-only mediation
// dispatch).
package capsule

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/egress"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/resolver"
	"github.com/istr/strike/internal/transport"
)

const (
	resolverPort uint16 = 53
	mediatorPort uint16 = 443
)

// UpstreamLookupFunc resolves a name to addresses via the lane's
// declared DoT resolver. Identical signature to
// resolver.UpstreamFunc and mediator.UpstreamLookupFunc; PR-22
// passes the same closure to both.
type UpstreamLookupFunc func(ctx context.Context, name string) ([]netip.Addr, error)

// Records aggregates the per-step records the capsule collects for
// attestation. PR-22 stores these; PR-24 (or later) wires them
// into the deploy attestation envelope.
type Records struct {
	DNS         []resolver.QueryRecord
	Connections []mediator.ConnectionRecord
}

// ErrCapsuleClosed is returned by Start after Close/Stop.
var ErrCapsuleClosed = errors.New("capsule: closed")

// NetworkCapsule is a per-step network aggregate.
//
// Lifecycle: New -> Start -> (container runs) -> Stop -> Records.
// The capsule does not own the container; the executor runs it.
//
// Concurrency: Start and Stop are mutually exclusive via an
// internal mutex. The underlying resolver and mediator handle
// concurrent queries/connections themselves.
type NetworkCapsule struct {
	stepAddr    netip.Addr
	resolverUDP net.PacketConn
	mediatorTCP net.Listener
	resolverTCP net.Listener
	mediator    *mediator.Mediator
	ca          *transport.EphemeralCA
	resolver    *resolver.Resolver
	serveGroup  *errgroup.Group
	serveCancel context.CancelFunc
	stepName    string
	pastaArgs   []string
	state       capsuleState
	mu          sync.Mutex
}

type capsuleState int

const (
	stateNew capsuleState = iota
	stateStarted
	stateStopped
)

// New constructs a NetworkCapsule for one step.
//
//   - stepName identifies the step in records and logs.
//   - stepAddr is the loopback address allocated for this step.
//     Resolver listens on stepAddr:53 (UDP+TCP); mediator on
//     stepAddr:443 (TCP).
//   - peers enumerates the HTTPS peers the step may reach. Their
//     hosts become the resolver's allowlist; their full trust
//     configs become the mediator's peer map.
//   - ca is the lane-wide ephemeral CA, shared across all
//     capsules in the lane run. Not owned; the caller manages
//     CA.Close.
//   - upstreamLook resolves names via the lane's DoT resolver.
//     Must be non-nil and concurrency-safe.
func New(
	stepName string,
	stepAddr netip.Addr,
	peers []mediator.PeerTrust,
	ca *transport.EphemeralCA,
	upstreamLook UpstreamLookupFunc,
) (*NetworkCapsule, error) {
	if stepName == "" {
		return nil, errors.New("capsule: stepName must not be empty")
	}
	if !stepAddr.Is4() {
		return nil, fmt.Errorf("capsule: stepAddr must be IPv4, got %s", stepAddr)
	}
	if ca == nil {
		return nil, errors.New("capsule: ca must not be nil")
	}
	if upstreamLook == nil {
		return nil, errors.New("capsule: upstreamLook must not be nil")
	}

	allowlist := make([]transport.Host, len(peers))
	for i, p := range peers {
		allowlist[i] = p.Host
	}

	res, err := resolver.New(stepName, allowlist, resolver.UpstreamFunc(upstreamLook))
	if err != nil {
		return nil, fmt.Errorf("capsule: resolver: %w", err)
	}
	med, err := mediator.New(stepName, peers, ca, mediator.UpstreamLookupFunc(upstreamLook))
	if err != nil {
		return nil, fmt.Errorf("capsule: mediator: %w", err)
	}

	return &NetworkCapsule{
		stepName:  stepName,
		stepAddr:  stepAddr,
		resolver:  res,
		mediator:  med,
		ca:        ca,
		pastaArgs: egress.BuildPastaArgs(stepAddr, resolverPort, mediatorPort),
		state:     stateNew,
	}, nil
}

// PastaArgs returns a copy of the pasta options for this step.
func (c *NetworkCapsule) PastaArgs() []string {
	out := make([]string, len(c.pastaArgs))
	copy(out, c.pastaArgs)
	return out
}

// ResolverAddr returns the resolver's listening address, for use
// as the container's --dns flag.
func (c *NetworkCapsule) ResolverAddr() netip.AddrPort {
	return netip.AddrPortFrom(c.stepAddr, resolverPort)
}

// Start binds the resolver and mediator listeners and launches
// their serve goroutines. They run until Stop or until ctx is
// cancelled. Returns an error if binding fails or if the capsule
// is already started or stopped.
func (c *NetworkCapsule) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == stateStopped {
		return ErrCapsuleClosed
	}
	if c.state == stateStarted {
		return errors.New("capsule: already started")
	}

	resolverAddrStr := netip.AddrPortFrom(c.stepAddr, resolverPort).String()
	mediatorAddrStr := netip.AddrPortFrom(c.stepAddr, mediatorPort).String()

	lc := net.ListenConfig{}
	udp, err := lc.ListenPacket(ctx, "udp", resolverAddrStr)
	if err != nil {
		return fmt.Errorf("capsule: bind resolver UDP %s: %w", resolverAddrStr, err)
	}
	tcp, err := lc.Listen(ctx, "tcp", resolverAddrStr)
	if err != nil {
		closer.Warn(udp, "capsule resolver UDP")
		return fmt.Errorf("capsule: bind resolver TCP %s: %w", resolverAddrStr, err)
	}
	mtcp, err := lc.Listen(ctx, "tcp", mediatorAddrStr)
	if err != nil {
		closer.Warn(udp, "capsule resolver UDP")
		closer.Warn(tcp, "capsule resolver TCP")
		return fmt.Errorf("capsule: bind mediator TCP %s: %w", mediatorAddrStr, err)
	}

	c.resolverUDP = udp
	c.resolverTCP = tcp
	c.mediatorTCP = mtcp

	serveCtx, cancel := context.WithCancel(ctx)
	c.serveCancel = cancel
	g, gctx := errgroup.WithContext(serveCtx)
	c.serveGroup = g

	g.Go(func() error { return c.resolver.Serve(gctx, c.resolverUDP, c.resolverTCP) })
	g.Go(func() error { return c.mediator.Serve(gctx, c.mediatorTCP) })

	c.state = stateStarted
	return nil
}

// Stop cancels the serve goroutines, waits, and closes the
// listeners. Idempotent. Returns the first non-nil error from
// listener close or goroutine exit. Records remains callable
// after Stop.
func (c *NetworkCapsule) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == stateStopped {
		return nil
	}
	if c.state == stateNew {
		c.state = stateStopped
		return nil
	}

	c.serveCancel()
	serveErr := c.serveGroup.Wait()

	var firstErr error
	if err := c.resolverUDP.Close(); err != nil {
		firstErr = fmt.Errorf("capsule: resolver UDP close: %w", err)
	}
	if err := c.resolverTCP.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("capsule: resolver TCP close: %w", err)
	}
	if err := c.mediatorTCP.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("capsule: mediator TCP close: %w", err)
	}
	if serveErr != nil && firstErr == nil {
		firstErr = fmt.Errorf("capsule: serve: %w", serveErr)
	}

	c.state = stateStopped
	return firstErr
}

// Records returns a snapshot of DNS query records and connection
// records collected during serve. Callable before Start (empty),
// during, or after Stop (final).
func (c *NetworkCapsule) Records() Records {
	return Records{
		DNS:         c.resolver.Records(),
		Connections: c.mediator.Records(),
	}
}
