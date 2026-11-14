package endpoint

import (
	"encoding/json"
	"fmt"
)

// Endpoint is a declared endpoint with its server-trust anchor, discriminated
// by its carriage type: TLS or SSH. The CUE disjunction is annotated @go(-) so
// the generator skips it; this hand-written interface provides the Go-side
// union, as Engine does for the engine connection. The type names what the
// value is; the field that holds it names the role it plays.
type Endpoint interface {
	// Addr returns the endpoint's network address.
	Addr() Address
}

// Addr returns the endpoint's network address.
func (e TLS) Addr() Address { return e.Address }

// Addr returns the endpoint's network address.
func (e SSH) Addr() Address { return e.Address }

// UnmarshalEndpoint decodes one endpoint JSON object into the concrete branch
// named by its "type" discriminator. A missing or unknown type is an error, so
// a declaration fails when it is decoded, not when it is used. Exported for
// the lane step and capture decoders and for internal/deploy, which dispatch
// declared endpoints through it.
func UnmarshalEndpoint(data []byte) (Endpoint, error) {
	if len(data) == 0 || string(data) == "null" {
		return nil, fmt.Errorf("endpoint entry missing")
	}
	var probe struct {
		Type CarriageType `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("endpoint: %w", err)
	}
	switch probe.Type {
	case CarriageTypeHttps:
		var e TLS
		if err := e.UnmarshalJSON(data); err != nil {
			return nil, err
		}
		return e, nil
	case CarriageTypeSsh:
		var e SSH
		if err := e.UnmarshalJSON(data); err != nil {
			return nil, err
		}
		return e, nil
	case "":
		return nil, fmt.Errorf("endpoint missing type discriminator")
	default:
		return nil, fmt.Errorf("unknown endpoint type %q", probe.Type)
	}
}

// MarshalJSON projects the host to its packed authority wire form.
func (e TLS) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Trust Certificate  `json:"trust"`
		Type  CarriageType `json:"type"`
		Host  string       `json:"host"`
	}{Type: e.Type, Host: string(e.Address.Authority()), Trust: e.Trust})
}

// UnmarshalJSON parses the packed authority host into the address and decodes
// the trust anchor by field. Trust is required; a missing trust is an error.
func (e *TLS) UnmarshalJSON(data []byte) error {
	var aux struct {
		Trust *Certificate `json:"trust"`
		Type  CarriageType `json:"type"`
		Host  string       `json:"host"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("decode https endpoint: %w", err)
	}
	if aux.Trust == nil {
		return fmt.Errorf("https endpoint: trust required")
	}
	addr, err := ParseAuthority(aux.Host)
	if err != nil {
		return fmt.Errorf("https endpoint: %w", err)
	}
	*e = TLS{Type: aux.Type, Address: addr, Trust: *aux.Trust}
	return nil
}

// MarshalJSON projects the host to its packed authority wire form.
func (e SSH) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type       CarriageType `json:"type"`
		Host       string       `json:"host"`
		KnownHosts []HostKey    `json:"knownHosts"`
	}{Type: e.Type, Host: string(e.Address.Authority()), KnownHosts: e.KnownHosts})
}

// UnmarshalJSON parses the packed authority host into the address and carries
// the known-hosts set verbatim.
func (e *SSH) UnmarshalJSON(data []byte) error {
	var aux struct {
		Type       CarriageType `json:"type"`
		Host       string       `json:"host"`
		KnownHosts []HostKey    `json:"knownHosts"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("decode ssh endpoint: %w", err)
	}
	addr, err := ParseAuthority(aux.Host)
	if err != nil {
		return fmt.Errorf("ssh endpoint: %w", err)
	}
	*e = SSH{Type: aux.Type, Address: addr, KnownHosts: aux.KnownHosts}
	return nil
}
