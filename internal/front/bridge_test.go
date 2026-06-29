package front_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/front"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/transport"
)

// testUpstreamSSH is a minimal SSH server that accepts one session, echoes a
// known payload to stdout, writes a marker to stderr, and exits with a chosen
// status. It uses a fixed host key and accepts a single client public key.
type testUpstreamSSH struct {
	listener  net.Listener
	hostKey   ssh.Signer
	clientPub ssh.PublicKey
	payload   string
	stderr    string
	exitCode  uint32
}

func newTestUpstreamSSH(t *testing.T, clientPub ssh.PublicKey, payload, stderrMarker string, exitCode uint32) *testUpstreamSSH {
	t.Helper()
	_, priv, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		t.Fatal(genErr)
	}
	signer, sigErr := ssh.NewSignerFromKey(priv)
	if sigErr != nil {
		t.Fatal(sigErr)
	}
	var lc net.ListenConfig
	l, lisErr := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if lisErr != nil {
		t.Fatal(lisErr)
	}
	s := &testUpstreamSSH{
		listener:  l,
		hostKey:   signer,
		clientPub: clientPub,
		payload:   payload,
		stderr:    stderrMarker,
		exitCode:  exitCode,
	}
	go s.serve()
	return s
}

func (s *testUpstreamSSH) serve() {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(s.clientPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	cfg.AddHostKey(s.hostKey)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn, cfg)
	}
}

func (s *testUpstreamSSH) handleConn(conn net.Conn, cfg *ssh.ServerConfig) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("test upstream conn close: %v", err)
		}
	}()
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() {
		if err := sshConn.Close(); err != nil {
			log.Printf("test upstream ssh close: %v", err)
		}
	}()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			if rErr := newChan.Reject(ssh.UnknownChannelType, "no"); rErr != nil {
				log.Printf("test upstream reject: %v", rErr)
			}
			continue
		}
		channel, requests, aErr := newChan.Accept()
		if aErr != nil {
			return
		}
		s.handleSession(channel, requests)
		return
	}
}

func (s *testUpstreamSSH) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer func() {
		if err := channel.Close(); err != nil {
			log.Printf("test upstream channel close: %v", err)
		}
	}()
	for req := range requests {
		if req.Type != "exec" {
			testReply(req, false)
			continue
		}
		testReply(req, true)
		s.echoAndExit(channel)
		return
	}
}

func (s *testUpstreamSSH) echoAndExit(channel ssh.Channel) {
	if _, wErr := io.WriteString(channel, s.payload); wErr != nil {
		log.Printf("test upstream write stdout: %v", wErr)
	}
	if _, wErr := io.WriteString(channel.Stderr(), s.stderr); wErr != nil {
		log.Printf("test upstream write stderr: %v", wErr)
	}
	if cwErr := channel.CloseWrite(); cwErr != nil {
		log.Printf("test upstream close write: %v", cwErr)
	}
	exitPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(exitPayload, s.exitCode)
	if _, srErr := channel.SendRequest("exit-status", false, exitPayload); srErr != nil {
		log.Printf("test upstream send exit: %v", srErr)
	}
}

func testReply(req *ssh.Request, ok bool) {
	if req.WantReply {
		if rErr := req.Reply(ok, nil); rErr != nil {
			log.Printf("test reply: %v", rErr)
		}
	}
}

func (s *testUpstreamSSH) addr() string {
	return netip.MustParseAddrPort(s.listener.Addr().String()).Addr().String()
}

func (s *testUpstreamSSH) port() uint16 {
	return netip.MustParseAddrPort(s.listener.Addr().String()).Port()
}

func (s *testUpstreamSSH) hostKeyLine() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.hostKey.PublicKey())))
}

// startTestAgent starts an in-process SSH agent on a Unix socket, loads the
// given private key, and sets SSH_AUTH_SOCK for the duration of the test.
func startTestAgent(t *testing.T, priv ed25519.PrivateKey) {
	t.Helper()
	sockPath := t.TempDir() + "/agent.sock"
	var lc net.ListenConfig
	l, lisErr := lc.Listen(context.Background(), "unix", sockPath)
	if lisErr != nil {
		t.Fatal(lisErr)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Logf("agent listener close: %v", err)
		}
	})
	keyring := agent.NewKeyring()
	if addErr := keyring.Add(agent.AddedKey{PrivateKey: priv}); addErr != nil {
		t.Fatal(addErr)
	}
	go func() {
		for {
			conn, aErr := l.Accept()
			if aErr != nil {
				return
			}
			go func() {
				if sErr := agent.ServeAgent(keyring, conn); sErr != nil {
					log.Printf("test agent serve: %v", sErr)
				}
				if cErr := conn.Close(); cErr != nil {
					log.Printf("test agent conn close: %v", cErr)
				}
			}()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sockPath)
}

func bridgeTestCA(t *testing.T) *transport.EphemeralCA {
	t.Helper()
	ca, err := transport.New("bridge-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cErr := ca.Close(); cErr != nil {
			t.Logf("ca close: %v", cErr)
		}
	})
	return ca
}

// loopbackLookup resolves any name to 127.0.0.1.
func loopbackLookup(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

// dialFrontSSH connects to the front as an SSH client, sends the STRIKE_PEER
// env and runs the given command. Returns stdout, stderr, exit status.
func dialFrontSSH(t *testing.T, f *front.Front, token, cmd string) (string, string, int) {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.FixedHostKey(f.HostKeyPublic()),
	}
	conn, dialErr := ssh.Dial("tcp", f.Addr().String(), cfg)
	if dialErr != nil {
		t.Fatalf("dial front SSH: %v", dialErr)
	}
	defer func() {
		if cErr := conn.Close(); cErr != nil {
			t.Logf("ssh conn close: %v", cErr)
		}
	}()

	session, sessErr := conn.NewSession()
	if sessErr != nil {
		t.Fatalf("new session: %v", sessErr)
	}
	defer func() {
		if cErr := session.Close(); cErr != nil {
			t.Logf("session close: %v", cErr)
		}
	}()

	if envErr := session.Setenv("STRIKE_PEER", token); envErr != nil {
		t.Fatalf("setenv: %v", envErr)
	}

	stdout, pipeErr := session.StdoutPipe()
	if pipeErr != nil {
		t.Fatal(pipeErr)
	}
	stderr, pipeErr := session.StderrPipe()
	if pipeErr != nil {
		t.Fatal(pipeErr)
	}

	if startErr := session.Start(cmd); startErr != nil {
		t.Fatalf("start: %v", startErr)
	}

	outBytes, outErr := io.ReadAll(stdout)
	if outErr != nil {
		t.Fatalf("read stdout: %v", outErr)
	}
	errBytes, errReadErr := io.ReadAll(stderr)
	if errReadErr != nil {
		t.Fatalf("read stderr: %v", errReadErr)
	}

	exitStatus := 0
	if wErr := session.Wait(); wErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(wErr, &exitErr) {
			exitStatus = exitErr.ExitStatus()
		} else {
			t.Fatalf("wait: %v", wErr)
		}
	}

	return string(outBytes), string(errBytes), exitStatus
}

func TestBridge_EndToEnd(t *testing.T) {
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshClientPub, pubErr := ssh.NewPublicKey(clientPub)
	if pubErr != nil {
		t.Fatal(pubErr)
	}

	wantPayload := "hello from upstream\n"
	wantStderr := "stderr-marker\n"
	wantExit := uint32(42)
	upstream := newTestUpstreamSSH(t, sshClientPub, wantPayload, wantStderr, wantExit)
	t.Cleanup(func() {
		if cErr := upstream.listener.Close(); cErr != nil {
			t.Logf("upstream close: %v", cErr)
		}
	})

	startTestAgent(t, clientPriv)

	f, fErr := front.New(context.Background())
	if fErr != nil {
		t.Fatal(fErr)
	}
	t.Cleanup(func() {
		if cErr := f.Close(); cErr != nil {
			t.Logf("front close: %v", cErr)
		}
	})

	ca := bridgeTestCA(t)
	hp := capsule.HostPorts{Resolver: 15400, Mediator: 15401}
	targets := []capsule.SSHTarget{{
		Host:     primitive.Host(upstream.addr()),
		HostKeys: []string{upstream.hostKeyLine()},
		Port:     upstream.port(),
	}}

	caps, capsErr := capsule.New("bridge-step", hp, nil, targets, 40000, ca, loopbackLookup)
	if capsErr != nil {
		t.Fatalf("capsule.New: %v", capsErr)
	}

	tokens := caps.Tokens()
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if regErr := f.Register(tokens[0], caps); regErr != nil {
		t.Fatal(regErr)
	}
	f.Start(context.Background())

	gotOut, gotErr, gotExit := dialFrontSSH(t, f, tokens[0], "git-upload-pack 'repo'")

	if gotOut != wantPayload {
		t.Errorf("stdout = %q, want %q", gotOut, wantPayload)
	}
	if gotErr != wantStderr {
		t.Errorf("stderr = %q, want %q", gotErr, wantStderr)
	}
	if gotExit != int(wantExit) {
		t.Errorf("exit = %d, want %d", gotExit, wantExit)
	}

	sshRecs := caps.Records().SSH
	if len(sshRecs) != 1 {
		t.Fatalf("expected 1 SSH record, got %d", len(sshRecs))
	}
	if got := sshRecs[0].HostKeyFingerprint; !strings.HasPrefix(got, "sha256:") {
		t.Errorf("HostKeyFingerprint = %q, want sha256: prefix", got)
	}
	if sshRecs[0].HostKeyAlgo == "" {
		t.Error("HostKeyAlgo is empty")
	}
	if len(sshRecs[0].Resolved) == 0 {
		t.Error("Resolved is empty")
	}
}

func TestBridge_WrongToken_Refused(t *testing.T) {
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshClientPub, pubErr := ssh.NewPublicKey(clientPub)
	if pubErr != nil {
		t.Fatal(pubErr)
	}

	upstream := newTestUpstreamSSH(t, sshClientPub, "x", "", 0)
	t.Cleanup(func() {
		if cErr := upstream.listener.Close(); cErr != nil {
			t.Logf("upstream close: %v", cErr)
		}
	})
	startTestAgent(t, clientPriv)

	f, fErr := front.New(context.Background())
	if fErr != nil {
		t.Fatal(fErr)
	}
	t.Cleanup(func() {
		if cErr := f.Close(); cErr != nil {
			t.Logf("front close: %v", cErr)
		}
	})

	ca := bridgeTestCA(t)
	hp := capsule.HostPorts{Resolver: 15410, Mediator: 15411}
	targets := []capsule.SSHTarget{{
		Host:     primitive.Host(upstream.addr()),
		HostKeys: []string{upstream.hostKeyLine()},
		Port:     upstream.port(),
	}}
	caps, capsErr := capsule.New("wrong-tok", hp, nil, targets, 40000, ca, loopbackLookup)
	if capsErr != nil {
		t.Fatal(capsErr)
	}
	tokens := caps.Tokens()
	if regErr := f.Register(tokens[0], caps); regErr != nil {
		t.Fatal(regErr)
	}
	f.Start(context.Background())

	cfg := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.FixedHostKey(f.HostKeyPublic()),
	}
	conn, dialErr := ssh.Dial("tcp", f.Addr().String(), cfg)
	if dialErr != nil {
		t.Fatal(dialErr)
	}
	defer func() {
		if cErr := conn.Close(); cErr != nil {
			t.Logf("conn close: %v", cErr)
		}
	}()
	session, sessErr := conn.NewSession()
	if sessErr != nil {
		t.Fatal(sessErr)
	}
	defer func() {
		if cErr := session.Close(); cErr != nil {
			t.Logf("session close: %v", cErr)
		}
	}()
	if envErr := session.Setenv("STRIKE_PEER", "wrong-token-value"); envErr != nil {
		t.Logf("setenv: %v", envErr)
	}
	if startErr := session.Start("git-upload-pack 'x'"); startErr == nil {
		t.Error("expected error for wrong token, got nil")
	}
}

func TestBridge_InboundCloseUnblocksHandler(t *testing.T) {
	// Simulate pasta closing the inbound when the container is reaped:
	// the front's sshConn.Wait() must return (no hang).
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshClientPub, pubErr := ssh.NewPublicKey(clientPub)
	if pubErr != nil {
		t.Fatal(pubErr)
	}

	wantPayload := "inbound-close-test\n"
	upstream := newTestUpstreamSSH(t, sshClientPub, wantPayload, "", 0)
	t.Cleanup(func() {
		if cErr := upstream.listener.Close(); cErr != nil {
			t.Logf("upstream close: %v", cErr)
		}
	})
	startTestAgent(t, clientPriv)

	f, fErr := front.New(context.Background())
	if fErr != nil {
		t.Fatal(fErr)
	}
	t.Cleanup(func() {
		if cErr := f.Close(); cErr != nil {
			t.Logf("front close: %v", cErr)
		}
	})

	ca := bridgeTestCA(t)
	hp := capsule.HostPorts{Resolver: 15430, Mediator: 15431}
	targets := []capsule.SSHTarget{{
		Host:     primitive.Host(upstream.addr()),
		HostKeys: []string{upstream.hostKeyLine()},
		Port:     upstream.port(),
	}}
	caps, capsErr := capsule.New("inbound-close", hp, nil, targets, 40000, ca, loopbackLookup)
	if capsErr != nil {
		t.Fatal(capsErr)
	}
	tokens := caps.Tokens()
	if regErr := f.Register(tokens[0], caps); regErr != nil {
		t.Fatal(regErr)
	}
	f.Start(context.Background())

	// Dial the front and run a bridge.
	cfg := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.FixedHostKey(f.HostKeyPublic()),
	}
	conn, dialErr := ssh.Dial("tcp", f.Addr().String(), cfg)
	if dialErr != nil {
		t.Fatal(dialErr)
	}

	session, sessErr := conn.NewSession()
	if sessErr != nil {
		t.Fatal(sessErr)
	}

	if envErr := session.Setenv("STRIKE_PEER", tokens[0]); envErr != nil {
		t.Fatalf("setenv: %v", envErr)
	}
	stdout, pipeErr := session.StdoutPipe()
	if pipeErr != nil {
		t.Fatal(pipeErr)
	}
	if startErr := session.Start("git-upload-pack 'repo'"); startErr != nil {
		t.Fatal(startErr)
	}
	// Read all output first to let the bridge complete.
	outBytes, readErr := io.ReadAll(stdout)
	if readErr != nil {
		t.Fatalf("read stdout: %v", readErr)
	}
	if string(outBytes) != wantPayload {
		t.Errorf("stdout = %q, want %q", outBytes, wantPayload)
	}
	// Wait for session to get exit-status.
	if wErr := session.Wait(); wErr != nil {
		var exitErr *ssh.ExitError
		if !errors.As(wErr, &exitErr) {
			t.Fatalf("session wait: %v", wErr)
		}
	}

	// Now close the client connection (simulating what pasta does on reap).
	// The front's sshConn.Wait() must return and handleConn must exit.
	// If it hangs, the test times out.
	if cErr := conn.Close(); cErr != nil {
		t.Logf("conn close: %v", cErr)
	}
}

func TestBridge_DisallowedCommand_Refused(t *testing.T) {
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshClientPub, pubErr := ssh.NewPublicKey(clientPub)
	if pubErr != nil {
		t.Fatal(pubErr)
	}

	upstream := newTestUpstreamSSH(t, sshClientPub, "x", "", 0)
	t.Cleanup(func() {
		if cErr := upstream.listener.Close(); cErr != nil {
			t.Logf("upstream close: %v", cErr)
		}
	})
	startTestAgent(t, clientPriv)

	f, fErr := front.New(context.Background())
	if fErr != nil {
		t.Fatal(fErr)
	}
	t.Cleanup(func() {
		if cErr := f.Close(); cErr != nil {
			t.Logf("front close: %v", cErr)
		}
	})

	ca := bridgeTestCA(t)
	hp := capsule.HostPorts{Resolver: 15420, Mediator: 15421}
	targets := []capsule.SSHTarget{{
		Host:     primitive.Host(upstream.addr()),
		HostKeys: []string{upstream.hostKeyLine()},
		Port:     upstream.port(),
	}}
	caps, capsErr := capsule.New("bad-cmd", hp, nil, targets, 40000, ca, loopbackLookup)
	if capsErr != nil {
		t.Fatal(capsErr)
	}
	tokens := caps.Tokens()
	if regErr := f.Register(tokens[0], caps); regErr != nil {
		t.Fatal(regErr)
	}
	f.Start(context.Background())

	cfg := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.FixedHostKey(f.HostKeyPublic()),
	}
	conn, dialErr := ssh.Dial("tcp", f.Addr().String(), cfg)
	if dialErr != nil {
		t.Fatal(dialErr)
	}
	defer func() {
		if cErr := conn.Close(); cErr != nil {
			t.Logf("conn close: %v", cErr)
		}
	}()
	session, sessErr := conn.NewSession()
	if sessErr != nil {
		t.Fatal(sessErr)
	}
	defer func() {
		if cErr := session.Close(); cErr != nil {
			t.Logf("session close: %v", cErr)
		}
	}()
	if envErr := session.Setenv("STRIKE_PEER", tokens[0]); envErr != nil {
		t.Logf("setenv: %v", envErr)
	}
	if startErr := session.Start("rm -rf /"); startErr == nil {
		t.Error("expected error for disallowed command, got nil")
	}
}
