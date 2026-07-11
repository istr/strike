package stutter

// Address is a concept type carried by a field named after the wire noun it
// replaces; reading it back through Host() is the stutter the gate catches.
type Address struct{ host string }

// Host projects the address back to its host component.
func (a Address) Host() string { return a.host }

// URL is a concept type read through a same-named accessor: the legitimate
// projection the gate must not flag.
type URL struct{ raw string }

// URL returns the raw url.
func (u URL) URL() string { return u.raw }

type server struct {
	Host Address
	URL  URL
}

// bad reads a wire-noun-named field back through its same-named method; the
// static type Address differs from the accessor Host.
func bad(s server) string {
	return s.Host.Host() // want `stuttering accessor Host\.Host\(\)`
}

// good reads a field whose type name matches its accessor: not a stutter.
func good(s server) string {
	return s.URL.URL()
}
