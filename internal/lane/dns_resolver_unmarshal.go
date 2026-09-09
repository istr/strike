package lane

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
)

// unmarshalDNSResolver decodes a DNS resolver JSON object into endpoint.DoT:
// an authentication domain name, the IP the dial routes to, an optional port,
// and the root certificate the presented chain is verified against. The anchor
// is the same shape a peer declares, narrowed to the rootca mode: a
// certificate pinned as a leaf authenticates nothing here (RFC 8310 section
// 6.6, ADR-028), so mode leaf is a parse error on this endpoint and valid on
// every other.
//
// This decode lives in package lane (not endpoint) because lane owns the lane
// wire and the directional dependency is lane -> endpoint, never the reverse.
func unmarshalDNSResolver(data []byte) (endpoint.DoT, error) {
	var aux struct {
		Port  *primitive.Port       `json:"port"`
		Trust *endpoint.Certificate `json:"trust"`
		ADN   string                `json:"adn"`
		IP    string                `json:"ip"`
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
	if aux.Trust == nil {
		return endpoint.DoT{}, fmt.Errorf("resolver: trust required")
	}
	if aux.Trust.Mode != endpoint.CertificateModeRootca {
		return endpoint.DoT{}, fmt.Errorf(
			"resolver: trust mode %q is not accepted; the resolver accepts "+
				"rootca alone, because an authentication domain name is "+
				"verified against a certification path and a pinned leaf is "+
				"not one (RFC 8310 section 6.6)", aux.Trust.Mode)
	}
	return endpoint.DoT{
		ADN:   primitive.Host(aux.ADN),
		IP:    primitive.IP(aux.IP),
		Port:  aux.Port,
		Trust: *aux.Trust,
	}, nil
}
