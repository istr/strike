package deploy

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
)

// UnmarshalJSON implements json.Unmarshaler for Sealed.
// The peers field is a map of step names to peer slices; each
// peer entry needs discriminator-based dispatch into the
// appropriate concrete branch type. All other fields fall
// through to the default decoder.
func (s *Sealed) UnmarshalJSON(data []byte) error {
	type alias Sealed
	aux := struct {
		*alias
		Peers  map[string][]json.RawMessage `json:"peers,omitempty"`
		Engine json.RawMessage              `json:"engine,omitempty"`
	}{
		alias: (*alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.Engine) != 0 && string(aux.Engine) != "null" {
		conn, err := endpoint.UnmarshalEngine(aux.Engine)
		if err != nil {
			return fmt.Errorf("attestation engine: %w", err)
		}
		s.Engine = conn
	}
	if len(aux.Peers) == 0 {
		s.Peers = nil
		return nil
	}
	out := make(map[string][]lane.Peer, len(aux.Peers))
	for stepID, rawPeers := range aux.Peers {
		peers := make([]lane.Peer, len(rawPeers))
		for i, raw := range rawPeers {
			p, err := lane.UnmarshalPeer(raw)
			if err != nil {
				return fmt.Errorf("attestation peers[%q][%d]: %w", stepID, i, err)
			}
			peers[i] = p
		}
		out[stepID] = peers
	}
	s.Peers = out
	return nil
}
