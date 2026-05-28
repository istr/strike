// Package front is strike's lane-run control-plane front (ADR-038 D2): a
// single run-level component that will terminate container-facing SSH
// sessions, read the in-band capability token, and dispatch to per-step
// capsule contexts. This file is the skeleton. It owns one host-loopback
// listener and its lifecycle, exposes the listen address, and refuses every
// connection (fail-closed) until the terminating SSH server lands (ADR-038
// roadmap item 5). The capability token and the per-run dispatch table are
// ADR-038 roadmap item 2; both arrive with their first callers, not here.
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

// New binds the front to a kernel-assigned host-loopback port and starts its
// accept loop. The address is fixed for the lane run and read back via Addr;
// a configurable bind address is a later staging step (ADR-038 A1). The port
// is kernel-assigned rather than a fixed constant so concurrent lane runs on
// one host do not collide.
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
	go f.serve()
	return f, nil
}

// Addr returns the front's host-loopback listen address, fixed for the lane
// run. Later tracks point declared SSH peers at this address (ADR-038 roadmap
// items 3 and 4).
func (f *Front) Addr() netip.AddrPort {
	return f.addr
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
