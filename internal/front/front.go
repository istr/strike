// Package front is strike's lane-run control-plane front (ADR-038 D2): a
// single run-level component that will terminate container-facing SSH
// sessions, read the in-band capability token, and dispatch to per-step
// capsule contexts. It follows the bind-then-serve pattern: New binds the
// host-loopback listener and exposes the address (so lane setup can build
// state that depends on it), and Start launches the accept loop as the last
// setup step. Until the terminating SSH server lands (ADR-038) every
// accepted connection is refused (fail-closed). The front holds a
// flat token -> capsule dispatch map (ADR-038 D5): Register records a
// capsule's token, Lookup recovers the capsule. The map is built during the
// single-threaded setup phase and frozen before Start launches the accept
// loop, so it needs no lock.
package front

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/closer"
)

// Front is strike's lane-run control-plane front. It is constructed once per
// cmdRun, alongside the ephemeral CA, and closed at lane end.
type Front struct {
	hostKey  ssh.Signer
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
	_, priv, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		closer.Warn(l, "front listener")
		return nil, fmt.Errorf("front: host key: %w", keyErr)
	}
	signer, sErr := ssh.NewSignerFromKey(priv)
	if sErr != nil {
		closer.Warn(l, "front listener")
		return nil, fmt.Errorf("front: host signer: %w", sErr)
	}
	f := &Front{
		addr:     tcpAddr.AddrPort(),
		listener: l,
		dispatch: map[string]*capsule.NetworkCapsule{},
		hostKey:  signer,
	}
	return f, nil
}

// Addr returns the front's host-loopback listen address, fixed for the lane
// run. Later tracks point declared SSH peers at this address (ADR-038).
func (f *Front) Addr() netip.AddrPort {
	return f.addr
}

// Start launches the accept loop. Call it once, as the last setup step, after
// all lane setup that depends on the front's address (and any future dispatch
// state) is complete: New binds and exposes Addr for setup, Start begins
// accepting. Starting only after setup means the accept goroutine sees fully
// built, frozen setup state without locking. Not safe to call concurrently
// with Close. ctx is the lane-run context, threaded to each session's
// BridgePeer so an upstream resolve or agent dial cancels when the run ends;
// the accept loop itself is bounded by Close, not ctx.
func (f *Front) Start(ctx context.Context) {
	go f.serve(ctx)
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

// HostKeyPublic returns the front's synthetic SSH host key's public half,
// which seeds the container's known_hosts entry for the front.
func (f *Front) HostKeyPublic() ssh.PublicKey {
	return f.hostKey.PublicKey()
}

// serve accepts container-facing SSH connections, terminates each with the
// synthetic host key and none auth, reads the STRIKE_PEER token and the
// command, allowlists the command, looks up the capsule, and hands the
// channel to capsule.BridgePeer (ADR-038 D5). The front never dials the peer;
// the capsule does. The loop ends when Close closes the listener.
func (f *Front) serve(ctx context.Context) {
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(f.hostKey)
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handleConn(ctx, conn, cfg)
	}
}

func (f *Front) handleConn(ctx context.Context, conn net.Conn, cfg *ssh.ServerConfig) {
	sshConn, chans, reqs, hErr := ssh.NewServerConn(conn, cfg)
	if hErr != nil {
		// Handshake failed: sshConn does not own conn, so close it here.
		// Stray probes/keyscans land here and fail closed quietly.
		closer.Warn(conn, "front conn")
		return
	}
	// sshConn owns the underlying conn; closing it closes conn. Do not also
	// close conn, or the second close logs "use of closed network connection".
	defer closer.Warn(sshConn, "front ssh conn")
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			rejectErr := newChan.Reject(ssh.UnknownChannelType, "only session channels")
			if rejectErr != nil {
				log.Printf("WARN   front: reject non-session channel: %v", rejectErr)
			}
			continue
		}
		channel, requests, aErr := newChan.Accept()
		if aErr != nil {
			return
		}
		f.handleSession(ctx, channel, requests)
		break
	}
	// The front did not initiate this connection (the engine did, via pasta),
	// so it does not tear it down. After the session, wait for the client to
	// disconnect -- it does once it has the exit-status -- or for pasta to
	// close the inbound when the container is reaped. Either ends the Wait;
	// the deferred sshConn close is then a backstop on an already-closed conn.
	// No timer: the container lifecycle bounds the wait.
	// A client disconnect here (e.g. git's reason-11 "disconnected by user" at
	// clone end) is normal teardown, not a failure; x/crypto/ssh has no
	// exported disconnect type, so match the rendered error.
	if wErr := sshConn.Wait(); wErr != nil &&
		!closer.IsExpectedClose(wErr) &&
		!strings.Contains(wErr.Error(), "ssh: disconnect") {
		log.Printf("WARN   front: conn wait: %v", wErr)
	}
}

func (f *Front) handleSession(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer closer.Warn(channel, "front session channel")
	var token string
	for req := range requests {
		switch req.Type {
		case "env":
			token = f.handleEnv(req, token)
		case "exec":
			f.handleExec(ctx, req, channel, token)
			return
		default:
			replyReq(req, false)
		}
	}
}

func (f *Front) handleEnv(req *ssh.Request, token string) string {
	var env struct{ Name, Value string }
	if ssh.Unmarshal(req.Payload, &env) == nil && env.Name == "STRIKE_PEER" {
		token = env.Value
	}
	replyReq(req, true)
	return token
}

func (f *Front) handleExec(ctx context.Context, req *ssh.Request, channel ssh.Channel, token string) {
	var ex struct{ Command string }
	if ssh.Unmarshal(req.Payload, &ex) != nil || !allowedSSHCommand(ex.Command) {
		replyReq(req, false)
		return
	}
	caps, ok := f.Lookup(token)
	if !ok {
		replyReq(req, false)
		return
	}
	replyReq(req, true)
	status, bErr := caps.BridgePeer(ctx, channel, token, ex.Command)
	if bErr != nil {
		log.Printf("WARN   front: bridge peer: %v", bErr)
	}
	sendExitStatus(channel, status)
}

// replyReq sends a reply if the request wants one. Errors are logged.
func replyReq(req *ssh.Request, ok bool) {
	if req.WantReply {
		if err := req.Reply(ok, nil); err != nil {
			log.Printf("WARN   front: reply: %v", err)
		}
	}
}

// allowedSSHCommand permits only the two git transport commands (ADR-038 D1).
// The command arrives as "git-upload-pack 'path'" or "git-receive-pack 'path'".
func allowedSSHCommand(cmd string) bool {
	return strings.HasPrefix(cmd, "git-upload-pack ") ||
		strings.HasPrefix(cmd, "git-receive-pack ")
}

// sendExitStatus relays the upstream exit status on the container-facing
// channel (verified ADR-038 spike: uint32 big-endian, WantReply false, sent
// after data is flushed and CloseWrite'd, before the deferred Close).
func sendExitStatus(channel ssh.Channel, status uint32) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, status)
	if _, err := channel.SendRequest("exit-status", false, payload); err != nil {
		log.Printf("WARN   front: send exit-status: %v", err)
	}
}
