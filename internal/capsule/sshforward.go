package capsule

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/copier"
	"github.com/istr/strike/internal/mediator"
)

// SSHContainerPortBase is the first container-side port assigned to a
// unit's SSH peers. The k-th SSH peer (in peer-list order) is reached
// by the step's SSH client at 127.0.0.1:(SSHContainerPortBase+k). Port
// 22 is deliberately left unforwarded, so a connection that ignores the
// injected ssh_config fails closed instead of being misrouted.
const SSHContainerPortBase uint16 = 2200

// defaultSSHPort is the upstream port the forwarder dials when an SSH
// target host carries no explicit port.
const defaultSSHPort uint16 = 22

// pollInterval bounds Accept/Read blocking so serve loops notice ctx
// cancellation promptly without a separate wakeup channel.
const pollInterval = 200 * clock.Millisecond

// isTimeoutErr reports whether err is a deadline timeout (expected on
// each poll tick), as opposed to a real failure.
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// SSHTarget is one SSH peer the capsule forwards to: the declared
// upstream host (added to the resolver allowlist and resolved via the
// DoT resolver) and, implicitly, the upstream port the raw-TCP
// forwarder dials (the port suffix of Host, default 22).
type SSHTarget struct {
	Host string
}

// SSHConnectionRecord captures one SSH forward attempt for attestation.
// strike does not terminate or inspect SSH; the record confirms the
// connection to the declared peer succeeded (or why it failed). The
// validated host key lives in the lane's known_hosts entry (ADR-024).
type SSHConnectionRecord struct {
	Time     clock.Time
	Host     string // declared upstream host (no port)
	DestIP   string // resolved upstream IP actually dialed; empty on resolve error
	Err      string
	Decision mediator.Decision
	Port     uint16
}

// SplitSSHHostPort splits an SSH peer host into its host part and the
// upstream port to dial. A bare host yields defaultSSHPort. An invalid
// port suffix is treated as no port (host kept verbatim, defaultSSHPort).
func SplitSSHHostPort(h string) (string, uint16) {
	idx := strings.LastIndex(h, ":")
	if idx < 0 {
		return h, defaultSSHPort
	}
	host := h[:idx]
	p, err := strconv.ParseUint(h[idx+1:], 10, 16)
	if err != nil || p == 0 {
		return h, defaultSSHPort
	}
	return host, uint16(p)
}

// sshForwarder is a per-SSH-peer raw TCP relay bound to one host
// loopback port.
type sshForwarder struct {
	upstreamLook UpstreamLookupFunc
	stepName     string
	host         string
	records      []SSHConnectionRecord
	mu           sync.Mutex
	port         uint16
}

// newSSHForwarder constructs a forwarder for one SSH target.
func newSSHForwarder(stepName string, t SSHTarget, upstreamLook UpstreamLookupFunc) (*sshForwarder, error) {
	if upstreamLook == nil {
		return nil, errors.New("capsule: sshforward upstreamLook must not be nil")
	}
	host, port := SplitSSHHostPort(t.Host)
	if host == "" {
		return nil, fmt.Errorf("capsule: sshforward empty host in %q", t.Host)
	}
	return &sshForwarder{
		stepName:     stepName,
		host:         host,
		port:         port,
		upstreamLook: upstreamLook,
	}, nil
}

// serve accepts connections on l until ctx is done. Caller owns l;
// serve does not close it. Returns nil on clean ctx-cancellation.
func (f *sshForwarder) serve(ctx context.Context, l net.Listener) error {
	type deadliner interface {
		SetDeadline(t clock.Time) error
	}
	for ctx.Err() == nil {
		if d, ok := l.(deadliner); ok {
			if err := d.SetDeadline(clock.Wall().Add(pollInterval)); err != nil {
				return fmt.Errorf("capsule: sshforward set deadline: %w", err)
			}
		}
		conn, acceptErr := l.Accept()
		switch {
		case isTimeoutErr(acceptErr):
			continue
		case acceptErr != nil && ctx.Err() != nil:
			return nil
		case acceptErr != nil:
			return fmt.Errorf("capsule: sshforward accept: %w", acceptErr)
		}
		go f.handle(ctx, conn)
	}
	return nil
}

func (f *sshForwarder) handle(ctx context.Context, client net.Conn) {
	defer closer.Warn(client, "sshforward client conn")

	rec := SSHConnectionRecord{
		Time: clock.Wall(),
		Host: f.host,
		Port: f.port,
	}

	addrs, err := f.upstreamLook(ctx, f.host)
	if err != nil || len(addrs) == 0 {
		rec.Decision = mediator.DecisionError
		if err != nil {
			rec.Err = err.Error()
		} else {
			rec.Err = "no addresses resolved"
		}
		f.record(rec)
		return
	}
	dst := netip.AddrPortFrom(addrs[0], f.port)
	rec.DestIP = addrs[0].String()

	var d net.Dialer
	upstream, err := d.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		rec.Decision = mediator.DecisionError
		rec.Err = err.Error()
		f.record(rec)
		return
	}
	defer closer.Warn(upstream, "sshforward upstream conn")

	rec.Decision = mediator.DecisionAllowed
	f.record(rec)

	splice(client, upstream)
}

// splice copies bytes in both directions until either side closes.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copier.Forward(a, b, "sshforward a<-b") }()
	go func() { defer wg.Done(); copier.Forward(b, a, "sshforward b<-a") }()
	wg.Wait()
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
