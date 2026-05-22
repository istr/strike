package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/istr/strike/internal/clock"
)

const responseTTL = 60 // seconds; D19 / hard-coded

// processQuery parses a raw DNS query, applies the allowlist
// decision, calls upstream when permitted, builds a response,
// and appends a QueryRecord. Returns the response wire bytes or
// nil if the query was unparseable (in which case no response
// is sent; an unparseable query has no valid ID to echo).
func (r *Resolver) processQuery(_ context.Context, raw []byte) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(raw)
	if err != nil {
		return nil
	}
	q, err := parser.Question()
	if err != nil {
		return nil
	}

	qname, qtype := canonicalQName(q.Name), qTypeString(q.Type)

	// Non-A/AAAA: NOTIMP, no upstream call, no allowlist check.
	if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA {
		r.appendRecord(QueryRecord{
			Time:     clock.Wall(),
			QName:    qname,
			QType:    "OTHER",
			Decision: DecisionDenied,
		})
		return buildResponse(header, q, dnsmessage.RCodeNotImplemented, nil)
	}

	// Allowlist check.
	if _, ok := r.allowlist[qname]; !ok {
		r.appendRecord(QueryRecord{
			Time:     clock.Wall(),
			QName:    qname,
			QType:    qtype,
			Decision: DecisionDenied,
		})
		return buildResponse(header, q, dnsmessage.RCodeNameError, nil) // NXDOMAIN
	}

	// Synthesize the step's loopback address for allowed names. The
	// resolver contacts no upstream: the container connects to
	// synthAddr, where the step's mediator listens, and the mediator
	// performs the real upstream resolution and dial. For an A query
	// we answer synthAddr; for AAAA we answer NOERROR with no record
	// (synthAddr is IPv4; the empty AAAA nudges the container to the
	// A record under splice-only). See instruction 39.
	var answers []netip.Addr
	if q.Type == dnsmessage.TypeA {
		answers = []netip.Addr{r.synthAddr}
	}

	r.appendRecord(QueryRecord{
		Time:     clock.Wall(),
		QName:    qname,
		QType:    qtype,
		Decision: DecisionAllowed,
		Answers:  answers,
	})
	return buildResponse(header, q, dnsmessage.RCodeSuccess, answers)
}

func canonicalQName(n dnsmessage.Name) string {
	s := n.String()
	if len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return toLowerASCII(s)
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func qTypeString(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	default:
		return "OTHER"
	}
}

func buildResponse(reqHdr dnsmessage.Header, q dnsmessage.Question, rcode dnsmessage.RCode, answers []netip.Addr) []byte {
	respHdr := dnsmessage.Header{
		ID:                 reqHdr.ID,
		Response:           true,
		OpCode:             reqHdr.OpCode,
		Authoritative:      false, // AA=0; synthesizing forwarder
		Truncated:          false,
		RecursionDesired:   reqHdr.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	}
	builder := dnsmessage.NewBuilder(make([]byte, 0, 512), respHdr)
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil
	}
	if err := builder.Question(q); err != nil {
		return nil
	}
	if err := builder.StartAnswers(); err != nil {
		return nil
	}
	for _, addr := range answers {
		rh := dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  q.Type,
			Class: dnsmessage.ClassINET,
			TTL:   responseTTL,
		}
		switch q.Type {
		case dnsmessage.TypeA:
			if err := builder.AResource(rh, dnsmessage.AResource{A: addr.As4()}); err != nil {
				return nil
			}
		case dnsmessage.TypeAAAA:
			if err := builder.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: addr.As16()}); err != nil {
				return nil
			}
		}
	}
	raw, err := builder.Finish()
	if err != nil {
		return nil
	}
	return raw
}

func readTCPMessage(conn net.Conn) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf[:])
	if length == 0 {
		return nil, errors.New("resolver: zero-length tcp message")
	}
	msg := make([]byte, length)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeTCPMessage(conn net.Conn, msg []byte) error {
	n := len(msg)
	if n > 65535 {
		return fmt.Errorf("resolver: tcp message too large (%d bytes)", n)
	}
	lenBuf := [2]byte{byte(n >> 8), byte(n & 0xff)}
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := conn.Write(msg)
	return err
}
