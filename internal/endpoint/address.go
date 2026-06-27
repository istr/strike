// Package endpoint provides wire projections for the endpoint Address concept
// (ADR-048). Address itself is generated from contract/endpoint/address.cue;
// this file contains the hand-written behavior. The two convolute wire forms --
// a packed "host:port" authority and an "https://host:port/path" URL -- are
// projected here, not encoded in the type. Authority() and URL() round-trip
// the strings ParseAuthority and ParseURL accept.
package endpoint

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/istr/strike/internal/primitive"
)

// ParseAuthority parses a packed "host" or "host:port" authority into an
// Address. The host grammar admits one optional numeric port after the last
// ':'. An empty string, an empty host, or a port outside 1..65535 is an error.
// Path is nil: an authority carries no path.
func ParseAuthority(s string) (Address, error) {
	host := s
	var port *primitive.Port
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		host = s[:i]
		p, err := parsePort(s[i+1:])
		if err != nil {
			return Address{}, fmt.Errorf("invalid authority %q: %w", s, err)
		}
		port = &p
	}
	if host == "" {
		return Address{}, fmt.Errorf("invalid authority %q: empty host", s)
	}
	return Address{Host: primitive.Host(host), Port: port}, nil
}

// MustParseAuthority parses a packed authority, panicking on invalid input.
// Use only for known-good values and test fixtures.
func MustParseAuthority(s string) Address {
	a, err := ParseAuthority(s)
	if err != nil {
		panic(err)
	}
	return a
}

// ParseURL parses an "https://host[:port][/path]" base URL into an Address.
// Only the https scheme is accepted; host is required; port and path are
// optional. The path is preserved verbatim so URL() round-trips the input.
func ParseURL(s string) (Address, error) {
	const scheme = "https://"
	if !strings.HasPrefix(s, scheme) {
		return Address{}, fmt.Errorf("invalid url %q: must start with https://", s)
	}
	rest := s[len(scheme):]
	authority := rest
	var path *primitive.AbsPath
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority = rest[:i]
		ap := primitive.AbsPath(rest[i:])
		path = &ap
	}
	a, err := ParseAuthority(authority)
	if err != nil {
		return Address{}, fmt.Errorf("invalid url %q: %w", s, err)
	}
	a.Path = path
	return a, nil
}

// Authority returns the packed "host" or "host:port" wire form. A path, if
// present, is not included.
func (a Address) Authority() string {
	h := string(a.Host)
	if a.Port == nil {
		return h
	}
	p := int(*a.Port)
	return h + ":" + strconv.Itoa(p)
}

// URL returns the "https://host[:port][/path]" wire form. It round-trips an
// Address produced by ParseURL.
func (a Address) URL() string {
	s := "https://" + a.Authority()
	if a.Path != nil {
		p := string(*a.Path)
		s += p
	}
	return s
}

// parsePort parses a decimal port string into the 1..65535 range.
func parsePort(s string) (primitive.Port, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("port %q: not a number", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d: out of range 1..65535", n)
	}
	p := primitive.Port(n)
	return p, nil
}
