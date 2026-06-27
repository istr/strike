package endpoint

import (
	"encoding/json"
	"fmt"
)

// Engine is the control-plane-observed identity of the engine transport, a
// discriminated union over the connection kind. The CUE disjunction
// (#EngineUnix | #EngineTLS | #EngineMTLS) is annotated @go(-) so the generator
// skips it; this hand-written interface provides the Go-side union, mirroring
// Trust. Layer V (cpObserved): the control plane reads these facts off the TLS
// handshake itself.
type Engine interface {
	// ConnectionType returns the discriminator ("unix", "tls", "mtls").
	ConnectionType() string
}

// ConnectionType implements Engine.
func (c EngineUnix) ConnectionType() string { return c.Type }

// ConnectionType implements Engine.
func (c EngineTLS) ConnectionType() string { return c.Type }

// ConnectionType implements Engine.
func (c EngineMTLS) ConnectionType() string { return c.Type }

// UnmarshalEngine decodes one engine-connection JSON object into the concrete
// branch named by its "type" discriminator. Exported for internal/deploy, which
// dispatches sealed.engine through it. Mirrors the peer/observed-identity
// dispatch helpers.
func UnmarshalEngine(data []byte) (Engine, error) {
	if len(data) == 0 || string(data) == "null" {
		return nil, fmt.Errorf("engine connection missing")
	}
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("engine connection: %w", err)
	}
	switch probe.Type {
	case "unix":
		var c EngineUnix
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("decode unix engine connection: %w", err)
		}
		return c, nil
	case "tls":
		var c EngineTLS
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("decode tls engine connection: %w", err)
		}
		return c, nil
	case "mtls":
		var c EngineMTLS
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("decode mtls engine connection: %w", err)
		}
		return c, nil
	case "":
		return nil, fmt.Errorf("engine connection missing type discriminator")
	default:
		return nil, fmt.Errorf("unknown engine connection type %q", probe.Type)
	}
}
