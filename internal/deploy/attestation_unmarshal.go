package deploy

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
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
		Peers  map[primitive.Identifier][]json.RawMessage `json:"peers,omitempty"`
		Engine json.RawMessage                            `json:"engine,omitempty"`
	}{
		alias: (*alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	engine, peers, err := decodeEngineAndPeers(aux.Engine, aux.Peers)
	if err != nil {
		return fmt.Errorf("attestation %w", err)
	}
	s.Engine, s.Peers = engine, peers
	return nil
}

// UnmarshalJSON implements json.Unmarshaler for StrikeExternalParameters, the
// externalParameters of the sealed statement. It carries the same two
// hand-written unions as Sealed -- the declared peers and the engine
// connection -- and dispatches them the same way; all other fields fall
// through to the default decoder.
func (p *StrikeExternalParameters) UnmarshalJSON(data []byte) error {
	type alias StrikeExternalParameters
	aux := struct {
		*alias
		Peers  map[primitive.Identifier][]json.RawMessage `json:"peers,omitempty"`
		Engine json.RawMessage                            `json:"engine,omitempty"`
	}{
		alias: (*alias)(p),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	engine, peers, err := decodeEngineAndPeers(aux.Engine, aux.Peers)
	if err != nil {
		return fmt.Errorf("externalParameters %w", err)
	}
	p.Engine, p.Peers = engine, peers
	return nil
}

// decodeEngineAndPeers dispatches the engine connection and the declared peers
// through their union decoders. An absent or null engine decodes to nil, and an
// absent or empty peers map decodes to nil.
func decodeEngineAndPeers(rawEngine json.RawMessage, rawPeers map[primitive.Identifier][]json.RawMessage) (endpoint.Engine, map[primitive.Identifier][]lane.Peer, error) {
	var engine endpoint.Engine
	if len(rawEngine) != 0 && string(rawEngine) != "null" {
		conn, err := endpoint.UnmarshalEngine(rawEngine)
		if err != nil {
			return nil, nil, fmt.Errorf("engine: %w", err)
		}
		engine = conn
	}
	if len(rawPeers) == 0 {
		return engine, nil, nil
	}
	out := make(map[primitive.Identifier][]lane.Peer, len(rawPeers))
	for stepID, raws := range rawPeers {
		peers := make([]lane.Peer, len(raws))
		for i, raw := range raws {
			peer, err := lane.UnmarshalPeer(raw)
			if err != nil {
				return nil, nil, fmt.Errorf("peers[%q][%d]: %w", stepID, i, err)
			}
			peers[i] = peer
		}
		out[stepID] = peers
	}
	return engine, out, nil
}
