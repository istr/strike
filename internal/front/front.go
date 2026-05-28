// Package front is strike's lane-run control-plane front (ADR-038 D2): a
// single run-level component that will terminate container-facing SSH
// sessions, read the in-band capability token, and dispatch to per-step
// capsule contexts. It follows the bind-then-serve pattern: New binds the
// host-loopback listener and exposes the address (so lane setup can build
// state that depends on it), and Start launches the accept loop as the last
// setup step. Until the terminating SSH server lands (ADR-038 roadmap item
// 5) every accepted connection is refused (fail-closed). The capability token
// and the per-run dispatch table are later roadmap items and arrive with
// their first callers, not here.
package front

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/istr/strike/internal/closer"
)

// Front is strike's lane-run control-plane front. It is constructed once per
// cmdRun, alongside the ephemeral CA, and closed at lane end.
type Front struct {
	listener net.Listener
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
