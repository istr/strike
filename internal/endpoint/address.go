// Package endpoint provides wire projections for the endpoint Address concept
// (ADR-048). Address itself is generated from contract/endpoint/address.cue;
// this file contains the hand-written behavior. The three convolute wire forms
// -- a packed "host:port" authority, an "https://host:port/path" URL, and a
// bracket-delimited "[host]:port" host-port pair -- are projected here, not
// encoded in the type. Authority() and URL() round-trip the strings
// ParseAuthority and ParseURL accept; BracketedHostPort() is render-only. The
// JSON and String forms of an Address are its URL() form.
package endpoint

import (
	"encoding/json"
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
// optional; a query or fragment component is rejected. The path is preserved
// verbatim, and an input URL() would not render byte for byte -- a port with
// a leading zero or a sign -- is rejected rather than normalized, so every
// accepted string round-trips.
func ParseURL(s string) (Address, error) {
	const scheme = "https://"
	if !strings.HasPrefix(s, scheme) {
		return Address{}, fmt.Errorf("invalid url %q: must start with https://", s)
	}
	if strings.ContainsAny(s, "?#") {
		return Address{}, fmt.Errorf("invalid url %q: query and fragment are not permitted", s)
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
	if a.URL() != s {
		return Address{}, fmt.Errorf("invalid url %q: not in canonical form %q", s, a.URL())
	}
	return a, nil
}

// MustParseURL parses an https base URL, panicking on invalid input. Use only
// for known-good values and test fixtures.
func MustParseURL(s string) Address {
	a, err := ParseURL(s)
	if err != nil {
		panic(err)
	}
	return a
}

// Authority returns the packed "host" or "host:port" wire form. A path, if
// present, is not included.
func (a Address) Authority() Authority {
	if a.Port == nil {
		return Authority(a.Host.String())
	}
	return Authority(a.Host.String() + ":" + a.Port.String())
}

// URL returns the "https://host[:port][/path]" wire form. It round-trips an
// Address produced by ParseURL.
func (a Address) URL() string {
	s := "https://" + string(a.Authority())
	if a.Path != nil {
		p := a.Path.String()
		s += p
	}
	return s
}

// String returns the URL() form. The packed host:port keying of peers is the
// separate Authority type, not this method.
func (a Address) String() string {
	return a.URL()
}

// MarshalJSON emits the URL() form as a JSON string. The canonical form is a
// restricted URL limited to be compatible with the OIDC iss identifier.
func (a Address) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.URL())
}

// UnmarshalJSON decodes a JSON string through ParseURL, so a decoded Address
// always holds a canonical URL. Any other JSON value, null included, is an
// error.
func (a *Address) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("decode url: %w", err)
	}
	p, err := ParseURL(s)
	if err != nil {
		return err
	}
	*a = p
	return nil
}

// BracketedHostPort returns the host and port packed with the host enclosed in
// square brackets: the bare host when no port is set, and "[host]:port" when
// one is. A path, if present, is not included. The brackets are the delimiter
// the OpenSSH host grammar requires around a host carrying an explicit port;
// Authority packs the same pair without them.
func (a Address) BracketedHostPort() string {
	if a.Port == nil {
		return a.Host.String()
	}
	return "[" + a.Host.String() + "]:" + a.Port.String()
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
