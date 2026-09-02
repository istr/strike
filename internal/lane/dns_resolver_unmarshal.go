package lane

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
)

// unmarshalDNSResolver decodes a DNS resolver JSON object into endpoint.DoT:
// an authentication domain name, the IP the dial routes to, an optional port,
// and the CA bundle the presented chain is verified against. The anchor is
// decoded through the shared peer-trust mechanic so a resolver and a peer
// declare the same discriminated shape, and is then narrowed to the bundle
// arm: a leaf-certificate digest authenticates nothing here (RFC 8310 section
// 6.6, ADR-028), so certFingerprint is a parse error on this endpoint and
// valid on every other.
//
// This decode lives in package lane (not endpoint) because lane owns the
// shared peer-trust unmarshaling mechanic (unmarshalTLSTrust) and the
// directional dependency is lane -> endpoint, never the reverse.
func unmarshalDNSResolver(data []byte) (endpoint.DoT, error) {
	var aux struct {
		ADN   string          `json:"adn"`
		IP    string          `json:"ip"`
		Port  *primitive.Port `json:"port"`
		Trust json.RawMessage `json:"trust"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return endpoint.DoT{}, fmt.Errorf("decode resolver: %w", err)
	}
	if aux.ADN == "" {
		return endpoint.DoT{}, fmt.Errorf("resolver: adn required")
	}
	if aux.IP == "" {
		return endpoint.DoT{}, fmt.Errorf("resolver: ip required")
	}
	if len(aux.Trust) == 0 {
		return endpoint.DoT{}, fmt.Errorf("resolver: trust required")
	}
	t, err := unmarshalTLSTrust(aux.Trust)
	if err != nil {
		return endpoint.DoT{}, fmt.Errorf("resolver: %w", err)
	}
	bundle, ok := t.(endpoint.CABundle)
	if !ok {
		return endpoint.DoT{}, fmt.Errorf(
			"resolver: trust type %q is not accepted; the resolver accepts "+
				"caBundle alone, because an authentication domain name is "+
				"verified against a certification path and a leaf digest is "+
				"not one (RFC 8310 section 6.6)", t.TrustType())
	}
	return endpoint.DoT{
		ADN:   primitive.Host(aux.ADN),
		IP:    primitive.IP(aux.IP),
		Port:  aux.Port,
		Trust: bundle,
	}, nil
}
