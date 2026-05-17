package resolver_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/resolver"
	"github.com/istr/strike/internal/transport"
)

// Helpers for test setup.

func staticUpstream(addrs []netip.Addr) resolver.UpstreamFunc {
	return func(_ context.Context, _ string) ([]netip.Addr, error) {
		return addrs, nil
	}
}

func failingUpstream(msg string) resolver.UpstreamFunc {
	return func(_ context.Context, _ string) ([]netip.Addr, error) {
		return nil, errors.New(msg)
	}
}

func nopUpstream() resolver.UpstreamFunc {
	return staticUpstream(nil)
}

// startResolver creates a Resolver with ephemeral listeners and
// starts Serve in a goroutine. Returns the resolver, a
// stdlib *net.Resolver wired to the test DNS server's TCP
// listener, the UDP address, and a cancel function.
func startResolver(t *testing.T, allowlist []transport.Host, upstream resolver.UpstreamFunc) (*resolver.Resolver, *net.Resolver, string, context.CancelFunc) {
	t.Helper()
	r, err := resolver.New("test-step", allowlist, upstream)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var lc net.ListenConfig
	udp, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	tcp, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		closer.Warn(udp, "test udp")
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, udp, tcp) }()

	cleanup := func() {
		cancel()
		<-done
		closer.Warn(udp, "test udp")
		closer.Warn(tcp, "test tcp")
	}

	tcpAddr := tcp.Addr().String()
	udpAddr := udp.LocalAddr().String()

	stdRes := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(dialCtx, "tcp", tcpAddr)
		},
	}

	return r, stdRes, udpAddr, cleanup
}

// buildRawQuery builds a raw DNS query for the given name and type.
func buildRawQuery(name string, qtype dnsmessage.Type) ([]byte, error) {
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, err
	}
	builder := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{
		ID:               0x1234,
		RecursionDesired: true,
	})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

// udpQuery sends a raw DNS query via UDP and returns the response.
func udpQuery(t *testing.T, addr string, query []byte) []byte {
	t.Helper()
	conn, err := new(net.Dialer).DialContext(context.Background(), "udp", addr)
	if err != nil {
		t.Fatalf("udpQuery dial: %v", err)
	}
	defer closer.Warn(conn, "test udp conn")
	if _, writeErr := conn.Write(query); writeErr != nil {
		t.Fatalf("udpQuery write: %v", writeErr)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("udpQuery read: %v", err)
	}
	return buf[:n]
}

// parseRCode extracts the response code from a raw DNS response.
func parseRCode(t *testing.T, raw []byte) dnsmessage.RCode {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(raw)
	if err != nil {
		t.Fatalf("parseRCode: %v", err)
	}
	return h.RCode
}

// Tests.

func TestNew_RejectsEmptyStepName(t *testing.T) {
	_, err := resolver.New("", nil, nopUpstream())
	if err == nil {
		t.Fatal("expected error for empty stepName")
	}
}

func TestNew_RejectsNilUpstream(t *testing.T) {
	_, err := resolver.New("step", nil, nil)
	if err == nil {
		t.Fatal("expected error for nil upstream")
	}
}

func TestNew_EmptyAllowlistIsValid(t *testing.T) {
	r, stdRes, _, cleanup := startResolver(t, nil, nopUpstream())
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer cancel()

	_, err := stdRes.LookupHost(ctx, "anything.example.com")
	if err == nil {
		t.Fatal("expected error for denied name")
	}

	recs := r.Records()
	if len(recs) == 0 {
		t.Fatal("expected at least one record")
	}
	if recs[0].Decision != resolver.DecisionDenied {
		t.Errorf("Decision = %q, want denied", recs[0].Decision)
	}
}

func TestNew_NormalizesAllowlist(t *testing.T) {
	// All three entries should normalize to the same key.
	_, stdRes, _, cleanup := startResolver(t,
		[]transport.Host{"Example.COM", "example.com.", " example.com "},
		staticUpstream([]netip.Addr{netip.MustParseAddr("1.2.3.4")}),
	)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 2*clock.Second)
	defer cancel()

	addrs, err := stdRes.LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("expected at least one address")
	}
}

func TestServe_AllowedNameA(t *testing.T) {
	upstream := staticUpstream([]netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("1.2.3.5"),
		netip.MustParseAddr("::1"),
	})
	r, _, udpAddr, cleanup := startResolver(t,
		[]transport.Host{"allowed.example.com"},
		upstream,
	)
	defer cleanup()

	query, err := buildRawQuery("allowed.example.com", dnsmessage.TypeA)
	if err != nil {
		t.Fatalf("buildRawQuery: %v", err)
	}
	resp := udpQuery(t, udpAddr, query)

	rcode := parseRCode(t, resp)
	if rcode != dnsmessage.RCodeSuccess {
		t.Fatalf("RCode = %v, want Success", rcode)
	}

	recs := r.Records()
	if len(recs) == 0 {
		t.Fatal("expected at least one record")
	}
	rec := recs[0]
	if rec.Decision != resolver.DecisionAllowed {
		t.Errorf("Decision = %q, want allowed", rec.Decision)
	}
	if rec.QType != "A" {
		t.Errorf("QType = %q, want A", rec.QType)
	}
	// Should have exactly 2 IPv4 addresses, no IPv6.
	if len(rec.Answers) != 2 {
		t.Errorf("got %d answers, want 2: %v", len(rec.Answers), rec.Answers)
	}
	for _, a := range rec.Answers {
		if !a.Is4() {
			t.Errorf("expected IPv4, got %v", a)
		}
	}
}

func TestServe_AllowedNameAAAA(t *testing.T) {
	upstream := staticUpstream([]netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("1.2.3.5"),
		netip.MustParseAddr("2001:db8::1"),
	})
	r, _, udpAddr, cleanup := startResolver(t,
		[]transport.Host{"allowed.example.com"},
		upstream,
	)
	defer cleanup()

	query, err := buildRawQuery("allowed.example.com", dnsmessage.TypeAAAA)
	if err != nil {
		t.Fatalf("buildRawQuery: %v", err)
	}
	resp := udpQuery(t, udpAddr, query)
	rcode := parseRCode(t, resp)
	if rcode != dnsmessage.RCodeSuccess {
		t.Fatalf("RCode = %v, want Success", rcode)
	}
	recs := r.Records()
	if len(recs) == 0 {
		t.Fatal("expected at least one record")
	}
	if len(recs[0].Answers) != 1 {
		t.Errorf("got %d AAAA answers, want 1", len(recs[0].Answers))
	}
}

func TestServe_AllowedNameNoMatchingFamily(t *testing.T) {
	upstream := staticUpstream([]netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
	})
	r, _, udpAddr, cleanup := startResolver(t,
		[]transport.Host{"v4only.example.com"},
		upstream,
	)
	defer cleanup()

	query, err := buildRawQuery("v4only.example.com", dnsmessage.TypeAAAA)
	if err != nil {
		t.Fatalf("buildRawQuery: %v", err)
	}
	resp := udpQuery(t, udpAddr, query)
	rcode := parseRCode(t, resp)
	// NODATA: NOERROR with empty answer section.
	if rcode != dnsmessage.RCodeSuccess {
		t.Fatalf("RCode = %v, want Success (NODATA)", rcode)
	}
	recs := r.Records()
	if len(recs) == 0 {
		t.Fatal("expected at least one record")
	}
	if recs[0].Decision != resolver.DecisionAllowed {
		t.Errorf("Decision = %q, want allowed", recs[0].Decision)
	}
	if len(recs[0].Answers) != 0 {
		t.Errorf("got %d answers, want 0 (NODATA)", len(recs[0].Answers))
	}
}

func TestServe_DeniedName_NXDOMAIN(t *testing.T) {
	r, _, udpAddr, cleanup := startResolver(t,
		[]transport.Host{"allowed.example.com"},
		nopUpstream(),
	)
	defer cleanup()

	query, err := buildRawQuery("notallowed.example.com", dnsmessage.TypeA)
	if err != nil {
		t.Fatalf("buildRawQuery: %v", err)
	}
	resp := udpQuery(t, udpAddr, query)
	rcode := parseRCode(t, resp)
	if rcode != dnsmessage.RCodeNameError {
		t.Fatalf("RCode = %v, want NameError (NXDOMAIN)", rcode)
	}
	recs := r.Records()
	if len(recs) == 0 {
		t.Fatal("expected at least one record")
	}
	if recs[0].Decision != resolver.DecisionDenied {
		t.Errorf("Decision = %q, want denied", recs[0].Decision)
	}
}

func TestServe_NotImplementedType_MX(t *testing.T) {
	r, _, udpAddr, cleanup := startResolver(t,
		[]transport.Host{"allowed.example.com"},
		nopUpstream(),
	)
	defer cleanup()

	query, err := buildRawQuery("allowed.example.com", dnsmessage.TypeMX)
	if err != nil {
		t.Fatalf("buildRawQuery: %v", err)
	}
	resp := udpQuery(t, udpAddr, query)
	rcode := parseRCode(t, resp)
	if rcode != dnsmessage.RCodeNotImplemented {
		t.Fatalf("RCode = %v, want NotImplemented", rcode)
	}
	recs := r.Records()
	if len(recs) == 0 {
		t.Fatal("expected at least one record")
	}
	if recs[0].QType != "OTHER" {
		t.Errorf("QType = %q, want OTHER", recs[0].QType)
	}
	if recs[0].Decision != resolver.DecisionDenied {
		t.Errorf("Decision = %q, want denied", recs[0].Decision)
	}
}

func TestServe_UpstreamError_SERVFAIL(t *testing.T) {
	r, _, udpAddr, cleanup := startResolver(t,
		[]transport.Host{"fail.example.com"},
		failingUpstream("upstream boom"),
	)
	defer cleanup()

	query, err := buildRawQuery("fail.example.com", dnsmessage.TypeA)
	if err != nil {
		t.Fatalf("buildRawQuery: %v", err)
	}
	resp := udpQuery(t, udpAddr, query)
	rcode := parseRCode(t, resp)
	if rcode != dnsmessage.RCodeServerFailure {
		t.Fatalf("RCode = %v, want ServerFailure", rcode)
	}
	recs := r.Records()
	if len(recs) == 0 {
		t.Fatal("expected at least one record")
	}
	if recs[0].Decision != resolver.DecisionError {
		t.Errorf("Decision = %q, want error", recs[0].Decision)
	}
	if recs[0].Err == "" {
		t.Error("Err should be populated")
	}
}

func TestServe_RecordsCaptured(t *testing.T) {
	upstream := func(_ context.Context, name string) ([]netip.Addr, error) {
		if name == "fail.example.com" {
			return nil, errors.New("upstream fail")
		}
		return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
	}
	r, _, udpAddr, cleanup := startResolver(t,
		[]transport.Host{"allowed.example.com", "fail.example.com"},
		upstream,
	)
	defer cleanup()

	for _, tc := range []struct {
		name  string
		qtype dnsmessage.Type
	}{
		{"allowed.example.com", dnsmessage.TypeA},
		{"denied.example.com", dnsmessage.TypeA},
		{"fail.example.com", dnsmessage.TypeA},
	} {
		q, err := buildRawQuery(tc.name, tc.qtype)
		if err != nil {
			t.Fatalf("buildRawQuery %s: %v", tc.name, err)
		}
		udpQuery(t, udpAddr, q)
	}

	recs := r.Records()
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}

	decisions := map[resolver.Decision]int{}
	for _, rec := range recs {
		decisions[rec.Decision]++
	}
	if decisions[resolver.DecisionAllowed] != 1 {
		t.Errorf("allowed count = %d, want 1", decisions[resolver.DecisionAllowed])
	}
	if decisions[resolver.DecisionDenied] != 1 {
		t.Errorf("denied count = %d, want 1", decisions[resolver.DecisionDenied])
	}
	if decisions[resolver.DecisionError] != 1 {
		t.Errorf("error count = %d, want 1", decisions[resolver.DecisionError])
	}
}

func TestServe_ConcurrentQueries(t *testing.T) {
	upstream := staticUpstream([]netip.Addr{netip.MustParseAddr("1.2.3.4")})
	r, _, udpAddr, cleanup := startResolver(t,
		[]transport.Host{"a.example.com", "b.example.com"},
		upstream,
	)
	defer cleanup()

	const n = 50
	names := []string{"a.example.com", "b.example.com", "denied.example.com"}
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(idx int) {
			defer wg.Done()
			name := names[idx%len(names)]
			q, qErr := buildRawQuery(name, dnsmessage.TypeA)
			if qErr != nil {
				t.Errorf("goroutine %d buildRawQuery: %v", idx, qErr)
				return
			}
			udpQuery(t, udpAddr, q)
		}(i)
	}
	wg.Wait()

	recs := r.Records()
	if len(recs) != n {
		t.Errorf("got %d records, want %d", len(recs), n)
	}
}

func TestServe_ContextCancellation(t *testing.T) {
	r, err := resolver.New("test-step", nil, nopUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var lc net.ListenConfig
	udp, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer closer.Warn(udp, "test udp")
	tcp, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closer.Warn(tcp, "test tcp")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, udp, tcp) }()

	cancel()
	timer, timerCancel := context.WithTimeout(context.Background(), 500*clock.Millisecond)
	defer timerCancel()
	select {
	case serveErr := <-done:
		if serveErr != nil {
			t.Errorf("Serve returned error: %v", serveErr)
		}
	case <-timer.Done():
		t.Fatal("Serve did not return within 500ms of context cancellation")
	}
}

func TestServe_NilListenersRejected(t *testing.T) {
	r, err := resolver.New("test-step", nil, nopUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if serveErr := r.Serve(context.Background(), nil, nil); serveErr == nil {
		t.Fatal("expected error for nil listeners")
	}
}

func TestClose_Idempotent(t *testing.T) {
	r, err := resolver.New("test-step", nil, nopUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestClose_BeforeServe_ServeReturnsError(t *testing.T) {
	r, err := resolver.New("test-step", nil, nopUpstream())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if closeErr := r.Close(); closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}

	var lc net.ListenConfig
	udp, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer closer.Warn(udp, "test udp")
	tcp, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closer.Warn(tcp, "test tcp")

	serveErr := r.Serve(context.Background(), udp, tcp)
	if !errors.Is(serveErr, resolver.ErrResolverClosed) {
		t.Errorf("Serve err = %v, want ErrResolverClosed", serveErr)
	}
}

func TestTCPQuery_LengthPrefixed(t *testing.T) {
	upstream := staticUpstream([]netip.Addr{netip.MustParseAddr("10.0.0.1")})

	r, err := resolver.New("test-step",
		[]transport.Host{"tcp.example.com"},
		upstream,
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var lc net.ListenConfig
	udp, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer closer.Warn(udp, "test udp")
	tcp, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer closer.Warn(tcp, "test tcp")

	ctx, cancel := context.WithTimeout(context.Background(), 5*clock.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, udp, tcp) }()

	// Build raw query.
	query, err := buildRawQuery("tcp.example.com", dnsmessage.TypeA)
	if err != nil {
		t.Fatalf("buildRawQuery: %v", err)
	}

	// Open TCP, write length-prefixed query, read length-prefixed response.
	conn, err := new(net.Dialer).DialContext(ctx, "tcp", tcp.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer closer.Warn(conn, "test tcp conn")

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(query))) // #nosec G115 -- test query is always small
	if _, writeErr := conn.Write(lenBuf[:]); writeErr != nil {
		t.Fatalf("write len: %v", writeErr)
	}
	if _, writeErr := conn.Write(query); writeErr != nil {
		t.Fatalf("write query: %v", writeErr)
	}

	// Read response length.
	if readErr := conn.SetReadDeadline(clock.Wall().Add(2 * clock.Second)); readErr != nil {
		t.Fatalf("set read deadline: %v", readErr)
	}
	var respLenBuf [2]byte
	if _, readErr := conn.Read(respLenBuf[:]); readErr != nil {
		t.Fatalf("read response len: %v", readErr)
	}
	respLen := binary.BigEndian.Uint16(respLenBuf[:])
	resp := make([]byte, respLen)
	total := 0
	for total < int(respLen) {
		n, readErr := conn.Read(resp[total:])
		if readErr != nil {
			t.Fatalf("read response body: %v", readErr)
		}
		total += n
	}

	rcode := parseRCode(t, resp)
	if rcode != dnsmessage.RCodeSuccess {
		t.Fatalf("RCode = %v, want Success", rcode)
	}

	// Verify answer contains 10.0.0.1.
	var p dnsmessage.Parser
	if _, parseErr := p.Start(resp); parseErr != nil {
		t.Fatalf("parser Start: %v", parseErr)
	}
	if skipErr := p.SkipAllQuestions(); skipErr != nil {
		t.Fatalf("SkipAllQuestions: %v", skipErr)
	}
	rr, ansErr := p.Answer()
	if ansErr != nil {
		t.Fatalf("Answer: %v", ansErr)
	}
	if rr.Header.Type != dnsmessage.TypeA {
		t.Fatalf("answer type = %v, want A", rr.Header.Type)
	}
	aBody, ok := rr.Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatal("answer body is not *dnsmessage.AResource")
	}
	got := netip.AddrFrom4(aBody.A)
	want := netip.MustParseAddr("10.0.0.1")
	if got != want {
		t.Errorf("A record = %v, want %v", got, want)
	}

	cancel()
	<-done
}
