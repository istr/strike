package lane

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/transport"
)

// unmarshalDNSResolver decodes a DNS resolver JSON object into
// transport.DNSResolver. The Trust field is required; missing
// trust is a parse error.
//
// This function lives in package lane (not transport) because lane
// owns the peer-trust unmarshaling mechanics (unmarshalTLSTrust)
// and the directional dependency is lane -> transport, never the
// reverse.
func unmarshalDNSResolver(data []byte) (transport.DNSResolver, error) {
	type alias struct {
		Host  string          `json:"host"`
		Trust json.RawMessage `json:"trust"`
	}
	var aux alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return transport.DNSResolver{}, fmt.Errorf("decode resolver: %w", err)
	}
	if len(aux.Trust) == 0 {
		return transport.DNSResolver{}, fmt.Errorf("resolver: trust required")
	}
	t, err := unmarshalTLSTrust(aux.Trust)
	if err != nil {
		return transport.DNSResolver{}, fmt.Errorf("resolver: %w", err)
	}
	addr, err := endpoint.ParseAuthority(aux.Host)
	if err != nil {
		return transport.DNSResolver{}, fmt.Errorf("resolver host: %w", err)
	}
	return transport.DNSResolver{Address: addr, Trust: t}, nil
}
