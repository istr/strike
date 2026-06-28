package lane

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/endpoint"
)

// unmarshalDNSResolver decodes a DNS resolver JSON object into endpoint.TLS: a
// DoT resolver is a TLS-carriage endpoint (host authority + a single server
// trust anchor), so it reuses the TLS endpoint concept, with the resolver role
// expressed lane-side by the `resolver:` field. The Trust field is required;
// missing trust is a parse error.
//
// This decode lives in package lane (not endpoint) because lane owns the
// shared peer-trust unmarshaling mechanic (unmarshalTLSTrust) and the
// directional dependency is lane -> endpoint, never the reverse.
func unmarshalDNSResolver(data []byte) (endpoint.TLS, error) {
	type alias struct {
		Host  string          `json:"host"`
		Trust json.RawMessage `json:"trust"`
	}
	var aux alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return endpoint.TLS{}, fmt.Errorf("decode resolver: %w", err)
	}
	if len(aux.Trust) == 0 {
		return endpoint.TLS{}, fmt.Errorf("resolver: trust required")
	}
	t, err := unmarshalTLSTrust(aux.Trust)
	if err != nil {
		return endpoint.TLS{}, fmt.Errorf("resolver: %w", err)
	}
	addr, err := endpoint.ParseAuthority(aux.Host)
	if err != nil {
		return endpoint.TLS{}, fmt.Errorf("resolver host: %w", err)
	}
	return endpoint.TLS{Type: "https", Address: addr, Trust: t}, nil
}
