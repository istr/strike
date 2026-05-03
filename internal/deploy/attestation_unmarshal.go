package deploy

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/lane"
)

// UnmarshalJSON implements json.Unmarshaler for Attestation.
// The peers field is a map of step names to peer slices; each
// peer entry needs discriminator-based dispatch into the
// appropriate concrete branch type. All other fields fall
// through to the default decoder.
func (a *Attestation) UnmarshalJSON(data []byte) error {
	type alias Attestation
	aux := struct {
		*alias
		Peers map[string][]json.RawMessage `json:"peers,omitempty"`
	}{
		alias: (*alias)(a),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.Peers) == 0 {
		a.Peers = nil
		return nil
	}
	out := make(map[string][]lane.Peer, len(aux.Peers))
	for stepName, rawPeers := range aux.Peers {
		peers := make([]lane.Peer, len(rawPeers))
		for i, raw := range rawPeers {
			p, err := lane.UnmarshalPeer(raw)
			if err != nil {
				return fmt.Errorf("attestation peers[%q][%d]: %w", stepName, i, err)
			}
			peers[i] = p
		}
		out[stepName] = peers
	}
	a.Peers = out
	return nil
}
