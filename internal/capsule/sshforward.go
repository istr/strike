package capsule

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/mediator"
	"github.com/istr/strike/internal/primitive"
)

// defaultSSHPort is the upstream port the capsule dials when an SSH
// target host carries no explicit port.
const defaultSSHPort uint16 = 22

// SSHTarget is one SSH peer the capsule connects to: the declared upstream
// host (added to the resolver allowlist and resolved via the DoT resolver,
// the port suffix being the upstream port, default 22) and the peer's
// declared host keys. HostKeys are the lane's known_hosts entries for this
// peer ("<keyType> <base64>" lines, no host prefix); the capsule pins them
// when it dials the peer (the front, not the container, now validates the
// peer -- ADR-038 D5, left-to-right dialing).
type SSHTarget struct {
	Host     primitive.Host
	HostKeys []string
	Port     uint16 // upstream SSH port; 0 means use defaultSSHPort
}

// SSHConnectionRecord captures one SSH forward attempt for attestation.
// strike does not terminate or inspect SSH; on the allowed path the record
// carries the validated upstream host-key identity (the key the server
// presented that matched the declared known_hosts anchor, ADR-024) and the
// upstream IPs resolved for the peer. Identity fields are set only on
// DecisionAllowed; a failed interaction aborts the run before notarization.
type SSHConnectionRecord struct {
	Time               clock.Time
	Host               string           // declared upstream host (no port)
	HostKeyFingerprint primitive.Digest // "sha256:<hex>" of the validated host key; set on DecisionAllowed
	HostKeyAlgo        string           // host-key algorithm, e.g. "ssh-ed25519"; set on DecisionAllowed
	Err                string
	Decision           mediator.Decision
	Resolved           []netip.Addr // upstream IPs from the DoT lookup; dialed addr is Resolved[0]
	Port               uint16
}

// sshForwarder holds the per-SSH-peer state the capsule needs to dial that
// peer on behalf of the front (ADR-038 D5): the resolved upstream host and
// port, the lane DoT lookup, the live outbound clients, and the connection
// records. It no longer relays raw TCP -- the front terminates SSH and the
// capsule re-originates via BridgePeer. (Name retained pending the naming
// consistency pass.)
type sshForwarder struct {
	upstreamLook UpstreamLookupFunc
	stepID       string
	host         string
	clients      map[*ssh.Client]struct{}
	records      []SSHConnectionRecord
	mu           sync.Mutex
	port         uint16
}

// newSSHForwarder constructs a forwarder for one SSH target.
func newSSHForwarder(stepID string, t SSHTarget, upstreamLook UpstreamLookupFunc) (*sshForwarder, error) {
	if upstreamLook == nil {
		return nil, errors.New("capsule: sshforward upstreamLook must not be nil")
	}
	if t.Host == "" {
		return nil, fmt.Errorf("capsule: sshforward empty host in %q", t.Host)
	}
	port := t.Port
	if port == 0 {
		port = defaultSSHPort
	}
	return &sshForwarder{
		stepID:       stepID,
		host:         string(t.Host),
		port:         port,
		upstreamLook: upstreamLook,
	}, nil
}

func (f *sshForwarder) record(rec SSHConnectionRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, rec)
}

// Records returns a snapshot of this forwarder's records.
func (f *sshForwarder) Records() []SSHConnectionRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]SSHConnectionRecord, len(f.records))
	copy(out, f.records)
	return out
}

// trackClient registers a live outbound SSH client this forwarder opened to
// its peer, so closeClients can force it shut when the step's container is
// reaped (ADR-038 D5: the capsule closes the connections it initiated).
func (f *sshForwarder) trackClient(c *ssh.Client) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.clients == nil {
		f.clients = make(map[*ssh.Client]struct{})
	}
	f.clients[c] = struct{}{}
}

// untrackClient removes a client that closed on its own (normal bridge
// completion). Safe after closeClients cleared the set (delete on a nil map is
// a no-op).
func (f *sshForwarder) untrackClient(c *ssh.Client) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.clients, c)
}

// closeClients force-closes every still-open outbound client. Snapshots under
// the lock, then closes outside it (Close may block; do not hold mu across
// it). Closing a client unblocks any spliceSSH stuck on the upstream
// session.Wait. Idempotent.
func (f *sshForwarder) closeClients() {
	f.mu.Lock()
	clients := make([]*ssh.Client, 0, len(f.clients))
	for c := range f.clients {
		clients = append(clients, c)
	}
	f.clients = nil
	f.mu.Unlock()
	for _, c := range clients {
		closer.Warn(c, "capsule upstream conn (forced on reap)")
	}
}
