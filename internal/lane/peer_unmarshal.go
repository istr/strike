package lane

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/transport"
)

const jsonNull = "null"

// unmarshalPeer decodes a single peer JSON object into the
// appropriate concrete branch type based on the "type"
// discriminator. Returns an error for missing or unknown types
// so that lane.Parse fails at validate time, not at run time.
func unmarshalPeer(data []byte) (Peer, error) {
	if len(data) == 0 || string(data) == jsonNull {
		return nil, fmt.Errorf("peer entry missing")
	}

	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("peer: %w", err)
	}

	switch probe.Type {
	case "https":
		var p HTTPSPeer
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("decode https peer: %w", err)
		}
		return p, nil
	case "ssh":
		var p SSHPeer
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("decode ssh peer: %w", err)
		}
		return p, nil
	case "oci":
		var p OCIPeer
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("decode oci peer: %w", err)
		}
		return p, nil
	case "":
		return nil, fmt.Errorf("peer missing type discriminator")
	default:
		return nil, fmt.Errorf("unknown peer type %q", probe.Type)
	}
}

// unmarshalTLSTrust decodes a single trust JSON object into
// the appropriate concrete branch type based on the "mode"
// discriminator.
func unmarshalTLSTrust(data []byte) (transport.TLSTrust, error) {
	if len(data) == 0 || string(data) == jsonNull {
		return nil, fmt.Errorf("trust entry missing")
	}

	var probe struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("trust: %w", err)
	}

	switch probe.Mode {
	case "cert_fingerprint":
		var t transport.FingerprintTrust
		if err := json.Unmarshal(data, &t); err != nil {
			return nil, fmt.Errorf("decode cert_fingerprint trust: %w", err)
		}
		return t, nil
	case "ca_bundle":
		var t transport.CABundleTrust
		if err := json.Unmarshal(data, &t); err != nil {
			return nil, fmt.Errorf("decode ca_bundle trust: %w", err)
		}
		return t, nil
	case "":
		return nil, fmt.Errorf("trust missing mode discriminator")
	default:
		return nil, fmt.Errorf("unknown trust mode %q", probe.Mode)
	}
}

// UnmarshalJSON implements json.Unmarshaler for HTTPSPeer. It
// decodes the trust field through the discriminator helper.
// HTTPSPeer.Trust is required; missing trust is an error.
func (p *HTTPSPeer) UnmarshalJSON(data []byte) error {
	type alias HTTPSPeer
	aux := struct {
		*alias
		Trust json.RawMessage `json:"trust"`
	}{
		alias: (*alias)(p),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.Trust) == 0 {
		return fmt.Errorf("https peer: trust required")
	}
	t, err := unmarshalTLSTrust(aux.Trust)
	if err != nil {
		return fmt.Errorf("https peer: %w", err)
	}
	p.Trust = t
	return nil
}

// UnmarshalJSON implements json.Unmarshaler for OCIPeer. The
// trust field is optional; if absent, Trust remains nil.
func (p *OCIPeer) UnmarshalJSON(data []byte) error {
	type alias OCIPeer
	aux := struct {
		*alias
		Trust json.RawMessage `json:"trust,omitempty"`
	}{
		alias: (*alias)(p),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.Trust) == 0 || string(aux.Trust) == jsonNull {
		p.Trust = nil
		return nil
	}
	t, err := unmarshalTLSTrust(aux.Trust)
	if err != nil {
		return fmt.Errorf("oci peer: %w", err)
	}
	p.Trust = t
	return nil
}

// UnmarshalJSON implements json.Unmarshaler for Step. It
// decodes the peers field as a slice of typed Peer interfaces
// using the discriminator helper. All other fields fall through
// to the default decoder via the alias trick.
func (s *Step) UnmarshalJSON(data []byte) error {
	type alias Step
	aux := struct {
		*alias
		Peers []json.RawMessage `json:"peers,omitempty"`
	}{
		alias: (*alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.Peers) == 0 {
		s.Peers = nil
		return nil
	}
	out := make([]Peer, len(aux.Peers))
	for i, raw := range aux.Peers {
		p, err := unmarshalPeer(raw)
		if err != nil {
			return fmt.Errorf("step peers[%d]: %w", i, err)
		}
		out[i] = p
	}
	s.Peers = out
	return nil
}

// UnmarshalJSON implements json.Unmarshaler for StateCapture.
// Same dispatch as Step but on the StateCapture peers field.
func (sc *StateCapture) UnmarshalJSON(data []byte) error {
	type alias StateCapture
	aux := struct {
		*alias
		Peers []json.RawMessage `json:"peers,omitempty"`
	}{
		alias: (*alias)(sc),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.Peers) == 0 {
		sc.Peers = nil
		return nil
	}
	out := make([]Peer, len(aux.Peers))
	for i, raw := range aux.Peers {
		p, err := unmarshalPeer(raw)
		if err != nil {
			return fmt.Errorf("state_capture peers[%d]: %w", i, err)
		}
		out[i] = p
	}
	sc.Peers = out
	return nil
}

// UnmarshalPeer decodes a peer JSON object using the type
// discriminator. Exported for callers in other packages
// (e.g. internal/deploy) that need the same dispatch logic
// when their containing struct declares peers as []lane.Peer.
func UnmarshalPeer(data []byte) (Peer, error) {
	return unmarshalPeer(data)
}
