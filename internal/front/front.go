// Package front is strike's lane-run control-plane front (ADR-038 D2): a
// single run-level component that will terminate container-facing SSH
// sessions, read the in-band capability token, and dispatch to per-step
// capsule contexts. It follows the bind-then-serve pattern: New binds the
// host-loopback listener and exposes the address (so lane setup can build
// state that depends on it), and Start launches the accept loop as the last
// setup step. Until the terminating SSH server lands (ADR-038 roadmap item
// 5) every accepted connection is refused (fail-closed). The front holds a
// flat token -> capsule dispatch map (ADR-038 D5): Register records a
// capsule's token, Lookup recovers the capsule. The map is built during the
// single-threaded setup phase and frozen before Start launches the accept
// loop, so it needs no lock.
package front

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/closer"
)

// Front is strike's lane-run control-plane front. It is constructed once per
// cmdRun, alongside the ephemeral CA, and closed at lane end.
type Front struct {
	listener net.Listener
	dispatch map[string]*capsule.NetworkCapsule
	addr     netip.AddrPort
}

// New binds the front to a kernel-assigned host-loopback port and returns it
// ready for setup to query Addr; it does not accept connections until Start.
// The address is fixed for the lane run and read back via Addr; a
// configurable bind address is a later staging step (ADR-038 A1). The port is
// kernel-assigned rather than a fixed constant so concurrent lane runs on one
// host do not collide.
func New(ctx context.Context) (*Front, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("front: listen: %w", err)
	}
	tcpAddr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		closer.Warn(l, "front listener")
		return nil, fmt.Errorf("front: listener address is %T, want *net.TCPAddr", l.Addr())
	}
	f := &Front{
		addr:     tcpAddr.AddrPort(),
		listener: l,
		dispatch: map[string]*capsule.NetworkCapsule{},
	}
	return f, nil
}

// Addr returns the front's host-loopback listen address, fixed for the lane
// run. Later tracks point declared SSH peers at this address (ADR-038 roadmap
// items 3 and 4).
func (f *Front) Addr() netip.AddrPort {
	return f.addr
}

// Start launches the accept loop. Call it once, as the last setup step, after
// all lane setup that depends on the front's address (and any future dispatch
// state) is complete: New binds and exposes Addr for setup, Start begins
// accepting. Starting only after setup means the accept goroutine sees fully
// built, frozen setup state without locking. Not safe to call concurrently
// with Close.
func (f *Front) Start() {
	go f.serve()
}

// Close stops the front by closing the listener, which unblocks the accept
// loop and ends it. cmdRun closes exactly once; idempotency is not required.
func (f *Front) Close() error {
	return f.listener.Close()
}

// Register records token -> c in the dispatch map. Call only during the
// single-threaded setup phase, before Start; the map is frozen by the time
// the accept loop runs, so no lock is taken here or in Lookup -- correctness
// rests on the bind-then-serve ordering (the go in Start happens-after every
// Register). A duplicate token (astronomically unlikely across 256-bit
// values) is an error, not a silent overwrite.
func (f *Front) Register(token string, c *capsule.NetworkCapsule) error {
	if token == "" || c == nil {
		return fmt.Errorf("front: register: empty token or nil capsule")
	}
	if _, dup := f.dispatch[token]; dup {
		return fmt.Errorf("front: register: token collision")
	}
	f.dispatch[token] = c
	return nil
}

// Lookup recovers the capsule a token was issued by. ok is false for an
// unknown or absent token; the terminating server treats that as fail-closed
// (ADR-038 D5). Read only after Start, when the map is frozen; no lock.
func (f *Front) Lookup(token string) (*capsule.NetworkCapsule, bool) {
	c, ok := f.dispatch[token]
	return c, ok
}

// serve accepts and immediately refuses every connection. The front has no
// routing table and no upstream dial path until the terminating SSH server
// lands (ADR-038 roadmap item 5), so a connection that reaches it must fail
// closed, never be relayed. The loop ends when Close closes the listener.
func (f *Front) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		closer.Warn(conn, "front: refused pre-server connection")
	}
}
