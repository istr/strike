// Package capsule aggregates the per-step network components: the
// allowlist DNS resolver, the TLS mediator, the per-SSH-peer bridge
// holders the front dials through (ADR-038 D5), and the pasta egress
// filter argument list. A NetworkCapsule represents one step's bundled
// lifecycle.
//
// Architectural decisions: see docs/ADR-028-step-container-egress-mediation.md,
// "Decision" (NetworkCapsule aggregate) and "Universal mediation, no escape
// hatches" (universal capsule; no network-mode switch), and docs/ADR-033 for
// SSH peer egress.
package capsule

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sync/errgroup"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/copier"
	"github.com/istr/strike/internal/egress"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/primitive"
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
	stepID      string
	pastaArgs   []string
	sshForwards []*sshForwarder
	sshPins     [][]ssh.PublicKey
	sshTokens   []string
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
//   - stepID identifies the step in records and logs.
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
	stepID string,
	hostPorts HostPorts,
	peers []mediator.PeerTrust,
	sshTargets []SSHTarget,
	frontHostPort uint16,
	ca *transport.EphemeralCA,
	upstreamLook UpstreamLookupFunc,
) (*NetworkCapsule, error) {
	if err := validateNewArgs(stepID, sshTargets, frontHostPort, ca, upstreamLook); err != nil {
		return nil, err
	}

	allowlist := make([]primitive.Host, 0, len(peers)+len(sshTargets))
	for _, p := range peers {
		allowlist = append(allowlist, p.Address.Host)
	}
	for _, t := range sshTargets {
		allowlist = append(allowlist, t.Host)
	}

	res, err := resolver.New(stepID, allowlist, loopbackV4)
	if err != nil {
		return nil, fmt.Errorf("capsule: resolver: %w", err)
	}
	med, err := mediator.New(stepID, peers, ca, mediator.UpstreamLookupFunc(upstreamLook))
	if err != nil {
		return nil, fmt.Errorf("capsule: mediator: %w", err)
	}

	forwarders := make([]*sshForwarder, len(sshTargets))
	sshTokens := make([]string, len(sshTargets))
	sshPins := make([][]ssh.PublicKey, len(sshTargets))
	for k, t := range sshTargets {
		fwd, fErr := newSSHForwarder(stepID, t, upstreamLook)
		if fErr != nil {
			return nil, fmt.Errorf("capsule: ssh forwarder: %w", fErr)
		}
		forwarders[k] = fwd
		tok, tErr := mintToken()
		if tErr != nil {
			return nil, fmt.Errorf("capsule: ssh token: %w", tErr)
		}
		sshTokens[k] = tok
		pins, pErr := parseHostKeys(t.HostKeys)
		if pErr != nil {
			return nil, fmt.Errorf("capsule: ssh host keys for %q: %w", t.Host, pErr)
		}
		if len(pins) == 0 {
			return nil, fmt.Errorf("capsule: ssh peer %q has no host keys", t.Host)
		}
		sshPins[k] = pins
	}

	return &NetworkCapsule{
		stepID:      stepID,
		hostPorts:   hostPorts,
		resolver:    res,
		mediator:    med,
		sshForwards: forwarders,
		sshPins:     sshPins,
		sshTokens:   sshTokens,
		ca:          ca,
		pastaArgs:   egress.BuildPastaArgs(resolverPort, hostPorts.Resolver, mediatorPort, hostPorts.Mediator, frontForwardPort(sshTargets, frontHostPort)),
		state:       stateNew,
	}, nil
}

func validateNewArgs(stepID string, sshTargets []SSHTarget, frontHostPort uint16, ca *transport.EphemeralCA, upstreamLook UpstreamLookupFunc) error {
	if stepID == "" {
		return errors.New("capsule: stepID must not be empty")
	}
	if ca == nil {
		return errors.New("capsule: ca must not be nil")
	}
	if upstreamLook == nil {
		return errors.New("capsule: upstreamLook must not be nil")
	}
	if len(sshTargets) > 0 && frontHostPort == 0 {
		return errors.New("capsule: ssh targets require a front host port")
	}
	return nil
}

// frontForwardPort returns the front host port to forward into the container,
// or 0 when the capsule has no SSH peers (no SSH path to the front needed).
func frontForwardPort(sshTargets []SSHTarget, frontHostPort uint16) uint16 {
	if len(sshTargets) == 0 {
		return 0
	}
	return frontHostPort
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
// peers: one Host block per peer, sorted by host, each setting SetEnv
// STRIKE_PEER=<token> (the ADR-038 D5 routing capability by which the front
// recovers this capsule and peer). No Port directive is emitted: the
// container's SSH client uses the default port 22, which pasta forwards to
// the front. Returns nil when the capsule has no SSH peers.
func (c *NetworkCapsule) SSHConfig() []byte {
	if len(c.sshForwards) == 0 {
		return nil
	}
	type block struct {
		host  string
		token string
	}
	blocks := make([]block, len(c.sshForwards))
	for k := range c.sshForwards {
		blocks[k] = block{
			host:  c.sshForwards[k].host,
			token: c.sshTokens[k],
		}
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].host < blocks[j].host })

	var buf bytes.Buffer
	for _, b := range blocks {
		buf.WriteString("Host ")
		buf.WriteString(b.host)
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

// CloseOutbound force-closes every outbound SSH connection this capsule's
// forwarders still hold to their peers. The executor calls it once the step's
// container is fully reaped: by then any in-flight bridge is either done (its
// upstream already closed and untracked) or aborted (the container died
// mid-clone), and an aborted bridge blocked on the upstream session.Wait is
// unblocked here. The capsule closes only the connections it initiated (the
// peer outbounds); the front's inbound is the engine's, torn down by pasta.
// No lifecycle lock: sshForwards is fixed after New, and each forwarder guards
// its own clients. Idempotent.
func (c *NetworkCapsule) CloseOutbound() {
	for _, f := range c.sshForwards {
		f.closeClients()
	}
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

// parseHostKeys parses known_hosts-style "<keyType> <base64>" lines into
// public keys for host-key pinning.
func parseHostKeys(lines []string) ([]ssh.PublicKey, error) {
	out := make([]ssh.PublicKey, 0, len(lines))
	for _, ln := range lines {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ln))
		if err != nil {
			return nil, fmt.Errorf("parse host key %q: %w", ln, err)
		}
		out = append(out, pub)
	}
	return out, nil
}

// pinnedHostKey returns a HostKeyCallback that accepts the connection only if
// the presented host key matches one of pins (by marshaled wire bytes). A
// peer may declare several keys (multiple known_hosts entries); any one
// matches. Mismatch is fail-closed.
func pinnedHostKey(pins []ssh.PublicKey, matched *ssh.PublicKey) ssh.HostKeyCallback {
	want := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		want[string(p.Marshal())] = struct{}{}
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if _, ok := want[string(key.Marshal())]; ok {
			*matched = key
			return nil
		}
		return fmt.Errorf("capsule: ssh host key mismatch")
	}
}

// peerIndexForToken returns the SSH peer index a capability token was issued
// for, or false if the token is not this capsule's. O(n) over a handful of
// peers.
func (c *NetworkCapsule) peerIndexForToken(token string) (int, bool) {
	for k, t := range c.sshTokens {
		if t == token {
			return k, true
		}
	}
	return -1, false
}

// BridgePeer dials the real SSH peer this token was issued for and splices the
// container-facing channel to it, running the command cmd (already
// allowlisted by the front) on the upstream. The capsule holds the peer host-
// key pins and drives the host ssh-agent for client auth; the front never
// reaches the peer (ADR-038 D5, left-to-right dialing). Returns the upstream
// exit status; the caller relays it on the channel. The splice shape and
// close/exit ordering are the verified bridge (ADR-038 spike): three io.Copy
// goroutines (stdin, stdout+CloseWrite, stderr), wait for the upstream, then
// the caller sends exit-status before closing the channel.
func (c *NetworkCapsule) BridgePeer(ctx context.Context, channel ssh.Channel, token, cmd string) (uint32, error) {
	k, ok := c.peerIndexForToken(token)
	if !ok {
		return 255, fmt.Errorf("capsule: unknown token")
	}
	fwd := c.sshForwards[k]

	rec := SSHConnectionRecord{Time: clock.Wall(), Host: fwd.host, Port: fwd.port}
	addrs, lErr := fwd.upstreamLook(ctx, fwd.host)
	if lErr != nil || len(addrs) == 0 {
		rec.Decision = mediator.DecisionError
		if lErr != nil {
			rec.Err = lErr.Error()
		} else {
			rec.Err = "no addresses resolved"
		}
		fwd.record(rec)
		return 255, fmt.Errorf("capsule: resolve %q: %w", fwd.host, lErr)
	}
	rec.Resolved = addrs
	dst := netip.AddrPortFrom(addrs[0], fwd.port)

	agentSock := os.Getenv("SSH_AUTH_SOCK")
	if agentSock == "" {
		rec.Decision = mediator.DecisionError
		rec.Err = "SSH_AUTH_SOCK not set"
		fwd.record(rec)
		return 255, fmt.Errorf("capsule: SSH_AUTH_SOCK not set")
	}
	agentConn, aErr := transport.DialUnixSocket(ctx, agentSock)
	if aErr != nil {
		rec.Decision = mediator.DecisionError
		rec.Err = aErr.Error()
		fwd.record(rec)
		return 255, fmt.Errorf("capsule: agent dial: %w", aErr)
	}
	defer closer.Warn(agentConn, "capsule agent conn")
	agentClient := agent.NewClient(agentConn)

	var hostKey ssh.PublicKey
	clientCfg := &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(agentClient.Signers)},
		HostKeyCallback: pinnedHostKey(c.sshPins[k], &hostKey),
	}
	upstream, dErr := ssh.Dial("tcp", dst.String(), clientCfg)
	if dErr != nil {
		rec.Decision = mediator.DecisionError
		rec.Err = dErr.Error()
		fwd.record(rec)
		return 255, fmt.Errorf("capsule: upstream dial: %w", dErr)
	}
	defer closer.Warn(upstream, "capsule upstream conn")
	fwd.trackClient(upstream)
	defer fwd.untrackClient(upstream)

	sum := sha256.Sum256(hostKey.Marshal())
	rec.HostKeyFingerprint = primitive.DigestFromHex(hex.EncodeToString(sum[:]))
	rec.HostKeyAlgo = hostKey.Type()
	rec.Decision = mediator.DecisionAllowed
	fwd.record(rec)

	return spliceSSH(channel, upstream, cmd)
}

// spliceSSH runs cmd on the upstream connection and splices the channel to it.
// Verified close/exit ordering (ADR-038 spike): three goroutines (stdin,
// stdout, stderr); channel.CloseWrite after both stdout and stderr drain (they
// share the channel, so half-close waits for both); upstream exit status
// returned after all pumps finish.
func spliceSSH(channel ssh.Channel, upstream *ssh.Client, cmd string) (uint32, error) {
	session, sErr := upstream.NewSession()
	if sErr != nil {
		return 255, fmt.Errorf("capsule: upstream session: %w", sErr)
	}
	defer closer.Warn(session, "capsule upstream session")

	stdin, inErr := session.StdinPipe()
	if inErr != nil {
		return 255, fmt.Errorf("capsule: stdin pipe: %w", inErr)
	}
	stdout, outErr := session.StdoutPipe()
	if outErr != nil {
		return 255, fmt.Errorf("capsule: stdout pipe: %w", outErr)
	}
	stderr, errErr := session.StderrPipe()
	if errErr != nil {
		return 255, fmt.Errorf("capsule: stderr pipe: %w", errErr)
	}
	if startErr := session.Start(cmd); startErr != nil {
		return 255, fmt.Errorf("capsule: upstream exec: %w", startErr)
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		copier.Forward(stdin, channel, "capsule stdin")
	}()
	// stdout and stderr both write to the container channel, so we must
	// NOT call channel.CloseWrite until both finish. Use io.Copy (not
	// copier.Forward, which auto-half-closes) and CloseWrite after join.
	go func() {
		defer wg.Done()
		if _, cpErr := io.Copy(channel, stdout); cpErr != nil && !closer.IsExpectedClose(cpErr) {
			log.Printf("WARN   capsule stdout: copy: %v", cpErr)
		}
	}()
	go func() {
		defer wg.Done()
		if _, cpErr := io.Copy(channel.Stderr(), stderr); cpErr != nil && !closer.IsExpectedClose(cpErr) {
			log.Printf("WARN   capsule stderr: copy: %v", cpErr)
		}
	}()

	status := sshExitStatus(session.Wait())
	wg.Wait()
	if cwErr := channel.CloseWrite(); cwErr != nil && !closer.IsExpectedClose(cwErr) {
		log.Printf("WARN   capsule channel: half-close: %v", cwErr)
	}
	return status, nil
}

// sshExitStatus extracts the exit status from an ssh.Session.Wait error. A nil
// error is exit 0; an ExitError yields its status clamped to [0,255]; anything
// else is 255.
func sshExitStatus(err error) uint32 {
	if err == nil {
		return 0
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitStatus()
		if code >= 0 && code <= 255 {
			return uint32(code)
		}
	}
	return 255
}
