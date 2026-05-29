// Package capsule aggregates the per-step network components: the
// allowlist DNS resolver, the TLS mediator, the per-SSH-peer raw-TCP
// forwards, and the pasta egress filter argument list. A
// NetworkCapsule represents one step's bundled lifecycle.
//
// Architectural decisions: see docs/ROADMAP-ADR-028.md D25
// (NetworkCapsule aggregate) and D28 (universal capsule; no
// network-mode switch), and docs/ADR-033 for SSH peer egress.
package capsule

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/egress"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/resolver"
	"github.com/istr/strike/internal/transport"
)

const (
	// resolverPort and mediatorPort are the ports the container
	// sees: standard DNS (53) and HTTPS (443). pasta's -T/-U forwards
	// remap them to the per-step unprivileged host ports from
	// AllocatePorts.
	resolverPort uint16 = 53
	mediatorPort uint16 = 443
)

// loopbackV4 is the address every step's resolver and mediator listen
// on and the container reaches. pasta -T/-U forward the container's
// 53/443 to the step's host ports, so per-step distinctness lives in
// the port, not the address. Each step has its own netns, so the
// shared loopback never collides.
var loopbackV4 = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// UpstreamLookupFunc resolves a name to addresses via the lane's
// declared DoT resolver. Identical signature to
// mediator.UpstreamLookupFunc; the mediator uses this to resolve
// and dial real upstreams.
type UpstreamLookupFunc func(ctx context.Context, name string) ([]netip.Addr, error)

// Records aggregates the per-step records the capsule collects for
// attestation: DNS queries, mediated TLS connections, and SSH forward
// attempts. Wiring these into the signed deploy attestation envelope
// (the per-peer connections surface) is an open follow-up tracked in
// docs/ADR-033 and ADR-028.
type Records struct {
	DNS         []resolver.QueryRecord
	Connections []mediator.ConnectionRecord
	SSH         []SSHConnectionRecord
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
	sshForwards []*sshForwarder
	sshTokens   []string
	sshTCP      []net.Listener
	hostPorts   HostPorts
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
//   - hostPorts is the per-step host-port pair allocated by
//     AllocatePorts. The resolver binds 127.0.0.1:hostPorts.Resolver,
//     the mediator 127.0.0.1:hostPorts.Mediator; the container
//     reaches both via pasta on 127.0.0.1:53 and :443.
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
	hostPorts HostPorts,
	peers []mediator.PeerTrust,
	sshTargets []SSHTarget,
	ca *transport.EphemeralCA,
	upstreamLook UpstreamLookupFunc,
) (*NetworkCapsule, error) {
	if stepName == "" {
		return nil, errors.New("capsule: stepName must not be empty")
	}
	if ca == nil {
		return nil, errors.New("capsule: ca must not be nil")
	}
	if upstreamLook == nil {
		return nil, errors.New("capsule: upstreamLook must not be nil")
	}
	if len(sshTargets) != len(hostPorts.SSH) {
		return nil, fmt.Errorf("capsule: %d ssh targets but %d ssh host ports",
			len(sshTargets), len(hostPorts.SSH))
	}

	allowlist := make([]transport.Host, 0, len(peers)+len(sshTargets))
	for _, p := range peers {
		allowlist = append(allowlist, p.Host)
	}
	for _, t := range sshTargets {
		allowlist = append(allowlist, transport.Host(t.Host))
	}

	res, err := resolver.New(stepName, allowlist, loopbackV4)
	if err != nil {
		return nil, fmt.Errorf("capsule: resolver: %w", err)
	}
	med, err := mediator.New(stepName, peers, ca, mediator.UpstreamLookupFunc(upstreamLook))
	if err != nil {
		return nil, fmt.Errorf("capsule: mediator: %w", err)
	}

	forwarders := make([]*sshForwarder, len(sshTargets))
	sshFwds := make([]egress.SSHForward, len(sshTargets))
	sshTokens := make([]string, len(sshTargets))
	for k, t := range sshTargets {
		fwd, fErr := newSSHForwarder(stepName, t, upstreamLook)
		if fErr != nil {
			return nil, fmt.Errorf("capsule: ssh forwarder: %w", fErr)
		}
		forwarders[k] = fwd
		sshFwds[k] = egress.SSHForward{
			ContainerPort: SSHContainerPortBase + uint16(k),
			HostPort:      hostPorts.SSH[k],
		}
		tok, tErr := mintToken()
		if tErr != nil {
			return nil, fmt.Errorf("capsule: ssh token: %w", tErr)
		}
		sshTokens[k] = tok
	}

	return &NetworkCapsule{
		stepName:    stepName,
		hostPorts:   hostPorts,
		resolver:    res,
		mediator:    med,
		sshForwards: forwarders,
		sshTokens:   sshTokens,
		ca:          ca,
		pastaArgs:   egress.BuildPastaArgs(resolverPort, hostPorts.Resolver, mediatorPort, hostPorts.Mediator, sshFwds),
		state:       stateNew,
	}, nil
}

// mintToken returns a 256-bit capability token, hex-encoded (64 lowercase
// hex chars: a safe ssh_config SetEnv value, no quoting).
func mintToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// SSHConfig renders the byte-deterministic ssh_config for this capsule's SSH
// peers: one Host block per peer, sorted by host, each setting Port (the
// peer's container-side loopback port) and SetEnv STRIKE_PEER=<token> (the
// ADR-038 D5 routing capability by which the front recovers this capsule and
// peer). Returns nil when the capsule has no SSH peers. The Port directive is
// transitional -- it points at the per-peer forwarder today and is removed
// when the front becomes the live endpoint (close of the D5 token strand).
func (c *NetworkCapsule) SSHConfig() []byte {
	if len(c.sshForwards) == 0 {
		return nil
	}
	type block struct {
		host  string
		token string
		port  uint16
	}
	blocks := make([]block, len(c.sshForwards))
	for k := range c.sshForwards {
		blocks[k] = block{
			host:  c.sshForwards[k].host,
			token: c.sshTokens[k],
			port:  SSHContainerPortBase + uint16(k),
		}
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].host < blocks[j].host })

	var buf bytes.Buffer
	for _, b := range blocks {
		buf.WriteString("Host ")
		buf.WriteString(b.host)
		buf.WriteByte('\n')
		buf.WriteString("    Port ")
		buf.WriteString(strconv.FormatUint(uint64(b.port), 10))
		buf.WriteByte('\n')
		buf.WriteString("    SetEnv STRIKE_PEER=")
		buf.WriteString(b.token)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// Tokens returns a copy of this capsule's per-peer capability tokens, for the
// caller to register token -> capsule in the front's dispatch map.
func (c *NetworkCapsule) Tokens() []string {
	out := make([]string, len(c.sshTokens))
	copy(out, c.sshTokens)
	return out
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
	return netip.AddrPortFrom(loopbackV4, resolverPort)
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

	resolverAddrStr := netip.AddrPortFrom(loopbackV4, c.hostPorts.Resolver).String()
	mediatorAddrStr := netip.AddrPortFrom(loopbackV4, c.hostPorts.Mediator).String()

	// SO_REUSEADDR on the UDP socket allows binding 127.0.0.1 on the
	// resolver port even when another process (e.g. avahi-daemon on
	// mDNS port 5353, which the first mediated step's resolver port
	// coincides with) holds a wildcard bind on that port. Safe because
	// our bind is to a specific address (127.0.0.1) and a distinct
	// per-step port.
	reuseLC := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var opErr error
			if err := c.Control(func(fd uintptr) {
				if fd > math.MaxInt {
					opErr = errors.New("capsule: fd exceeds int range")
					return
				}
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return opErr
		},
	}
	lc := net.ListenConfig{}
	udp, err := reuseLC.ListenPacket(ctx, "udp", resolverAddrStr)
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

	c.sshTCP = make([]net.Listener, len(c.sshForwards))
	for k := range c.sshForwards {
		addr := netip.AddrPortFrom(loopbackV4, c.hostPorts.SSH[k]).String()
		sl, slErr := lc.Listen(ctx, "tcp", addr)
		if slErr != nil {
			closer.Warn(udp, "capsule resolver UDP")
			closer.Warn(tcp, "capsule resolver TCP")
			closer.Warn(mtcp, "capsule mediator TCP")
			for j := range k {
				closer.Warn(c.sshTCP[j], "capsule ssh TCP")
			}
			return fmt.Errorf("capsule: bind ssh TCP %s: %w", addr, slErr)
		}
		c.sshTCP[k] = sl
	}

	serveCtx, cancel := context.WithCancel(ctx)
	c.serveCancel = cancel
	g, gctx := errgroup.WithContext(serveCtx)
	c.serveGroup = g

	g.Go(func() error { return c.resolver.Serve(gctx, c.resolverUDP, c.resolverTCP) })
	g.Go(func() error { return c.mediator.Serve(gctx, c.mediatorTCP) })
	for k := range c.sshForwards {
		fwd, l := c.sshForwards[k], c.sshTCP[k]
		g.Go(func() error { return fwd.serve(gctx, l) })
	}

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
	for _, l := range c.sshTCP {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("capsule: ssh TCP close: %w", err)
		}
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
	var ssh []SSHConnectionRecord
	for _, f := range c.sshForwards {
		ssh = append(ssh, f.Records()...)
	}
	return Records{
		DNS:         c.resolver.Records(),
		Connections: c.mediator.Records(),
		SSH:         ssh,
	}
}
