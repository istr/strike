package lane

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
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
		Type endpoint.CarriageType `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("peer: %w", err)
	}

	switch probe.Type {
	case endpoint.CarriageTypeHttps:
		return unmarshalHTTPSPeer(data)
	case endpoint.CarriageTypeSsh:
		return unmarshalSSHPeer(data)
	case "":
		return nil, fmt.Errorf("peer missing type discriminator")
	default:
		return nil, fmt.Errorf("unknown peer type %q", probe.Type)
	}
}

// unmarshalHTTPSPeer decodes an https peer into an endpoint.TLS,
// dispatching the trust discriminator and parsing the packed authority host.
// Trust is required; missing trust is an error.
func unmarshalHTTPSPeer(data []byte) (Peer, error) {
	var aux struct {
		Type  endpoint.CarriageType `json:"type"`
		Host  string                `json:"host"`
		Trust json.RawMessage       `json:"trust"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return nil, fmt.Errorf("decode https peer: %w", err)
	}
	if len(aux.Trust) == 0 {
		return nil, fmt.Errorf("https peer: trust required")
	}
	t, err := unmarshalTLSTrust(aux.Trust)
	if err != nil {
		return nil, fmt.Errorf("https peer: %w", err)
	}
	addr, err := endpoint.ParseAuthority(aux.Host)
	if err != nil {
		return nil, fmt.Errorf("https peer: %w", err)
	}
	return endpoint.TLS{Type: aux.Type, Address: addr, Trust: t}, nil
}

// unmarshalSSHPeer decodes an ssh peer into an endpoint.SSH, parsing the
// packed authority host and carrying the known-hosts set verbatim.
func unmarshalSSHPeer(data []byte) (Peer, error) {
	var aux struct {
		Type       endpoint.CarriageType `json:"type"`
		Host       string                `json:"host"`
		KnownHosts []endpoint.HostKey    `json:"knownHosts"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return nil, fmt.Errorf("decode ssh peer: %w", err)
	}
	addr, err := endpoint.ParseAuthority(aux.Host)
	if err != nil {
		return nil, fmt.Errorf("ssh peer: %w", err)
	}
	return endpoint.SSH{Type: aux.Type, Address: addr, KnownHosts: aux.KnownHosts}, nil
}

// unmarshalTLSTrust decodes a single trust JSON object into
// the appropriate concrete branch type based on the "type"
// discriminator.
func unmarshalTLSTrust(data []byte) (endpoint.Trust, error) {
	if len(data) == 0 || string(data) == jsonNull {
		return nil, fmt.Errorf("trust entry missing")
	}

	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("trust: %w", err)
	}

	switch probe.Type {
	case "certFingerprint":
		var t endpoint.Fingerprint
		if err := json.Unmarshal(data, &t); err != nil {
			return nil, fmt.Errorf("decode certFingerprint trust: %w", err)
		}
		return t, nil
	case "caBundle":
		var t endpoint.CABundle
		if err := json.Unmarshal(data, &t); err != nil {
			return nil, fmt.Errorf("decode caBundle trust: %w", err)
		}
		return t, nil
	case "":
		return nil, fmt.Errorf("trust missing type discriminator")
	default:
		return nil, fmt.Errorf("unknown trust type %q", probe.Type)
	}
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

// UnmarshalJSON implements json.Unmarshaler for Capture.
// Same dispatch as Step but on the Capture peers field.
func (sc *Capture) UnmarshalJSON(data []byte) error {
	type alias Capture
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
			return fmt.Errorf("capture peers[%d]: %w", i, err)
		}
		out[i] = p
	}
	sc.Peers = out
	return nil
}

// unmarshalOIDCConfig decodes an OIDC config JSON object into
// OIDCConfig. The Trust field is an interface (endpoint.Trust) and
// requires discriminator dispatch via unmarshalTLSTrust.
func unmarshalOIDCConfig(data []byte) (OIDCConfig, error) {
	type alias struct {
		Issuer   string          `json:"issuer"`
		Audience string          `json:"audience"`
		Identity string          `json:"identity"`
		Trust    json.RawMessage `json:"trust"`
	}
	var aux alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return OIDCConfig{}, fmt.Errorf("decode oidc: %w", err)
	}
	if len(aux.Trust) == 0 {
		return OIDCConfig{}, fmt.Errorf("oidc: trust required")
	}
	t, err := unmarshalTLSTrust(aux.Trust)
	if err != nil {
		return OIDCConfig{}, fmt.Errorf("oidc: %w", err)
	}
	return OIDCConfig{
		Issuer:   aux.Issuer,
		Audience: aux.Audience,
		Identity: aux.Identity,
		Trust:    t,
	}, nil
}

// unmarshalKeyless decodes the keyless block: the mandatory endpoint set plus
// at most one trust-root source (inline trustRoot XOR trustRootRef). Declaring
// both is an error. Resolution of the source to a usable trust root is deferred
// to the verify boundary (late binding); this only parses and carries it.
func unmarshalKeyless(data []byte) (Keyless, error) {
	type alias struct {
		Endpoints    json.RawMessage `json:"endpoints"`
		TrustRoot    json.RawMessage `json:"trustRoot"`
		TrustRootRef json.RawMessage `json:"trustRootRef"`
	}
	var aux alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return Keyless{}, fmt.Errorf("decode keyless: %w", err)
	}
	eps, err := unmarshalKeylessEndpoints(aux.Endpoints)
	if err != nil {
		return Keyless{}, err
	}
	k := Keyless{Endpoints: eps}
	hasInline := len(aux.TrustRoot) != 0 && string(aux.TrustRoot) != jsonNull
	hasRef := len(aux.TrustRootRef) != 0 && string(aux.TrustRootRef) != jsonNull
	if hasInline && hasRef {
		return Keyless{}, fmt.Errorf("keyless: trustRoot and trustRootRef are mutually exclusive")
	}
	switch {
	case hasInline:
		var tr TrustedRootReplica
		if err := json.Unmarshal(aux.TrustRoot, &tr); err != nil {
			return Keyless{}, fmt.Errorf("decode trustRoot: %w", err)
		}
		k.TrustRoot = &tr
	case hasRef:
		var ref primitive.ImageRef
		if err := json.Unmarshal(aux.TrustRootRef, &ref); err != nil {
			return Keyless{}, fmt.Errorf("decode trustRootRef: %w", err)
		}
		k.TrustRootRef = ref
	}
	return k, nil
}

// unmarshalKeylessEndpoints decodes the keyless endpoint set. Each
// endpoint's Trust field is an interface (endpoint.Trust) and requires
// discriminator dispatch via unmarshalTLSTrust.
func unmarshalKeylessEndpoints(data []byte) (KeylessEndpoints, error) {
	type alias struct {
		Fulcio json.RawMessage `json:"fulcio"`
		Rekor  json.RawMessage `json:"rekor"`
		TSA    json.RawMessage `json:"tsa"`
	}
	var aux alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return KeylessEndpoints{}, fmt.Errorf("decode keyless: %w", err)
	}
	fulcio, err := unmarshalKeylessEndpoint("fulcio", aux.Fulcio)
	if err != nil {
		return KeylessEndpoints{}, err
	}
	rekor, err := unmarshalKeylessEndpoint("rekor", aux.Rekor)
	if err != nil {
		return KeylessEndpoints{}, err
	}
	tsa, err := unmarshalKeylessEndpoint("tsa", aux.TSA)
	if err != nil {
		return KeylessEndpoints{}, err
	}
	return KeylessEndpoints{Fulcio: fulcio, Rekor: rekor, TSA: tsa}, nil
}

// unmarshalKeylessEndpoint decodes one keyless endpoint, dispatching the
// endpoint.Trust discriminator. All three endpoints are mandatory inside a
// declared keyless block, and trust is mandatory per endpoint.
func unmarshalKeylessEndpoint(name string, data []byte) (endpoint.HTTPS, error) {
	if len(data) == 0 || string(data) == jsonNull {
		return endpoint.HTTPS{}, fmt.Errorf("keyless: %s required", name)
	}
	type alias struct {
		URL   string          `json:"url"`
		Trust json.RawMessage `json:"trust"`
	}
	var aux alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return endpoint.HTTPS{}, fmt.Errorf("decode keyless %s: %w", name, err)
	}
	if len(aux.Trust) == 0 {
		return endpoint.HTTPS{}, fmt.Errorf("keyless %s: trust required", name)
	}
	t, err := unmarshalTLSTrust(aux.Trust)
	if err != nil {
		return endpoint.HTTPS{}, fmt.Errorf("keyless %s: %w", name, err)
	}
	addr, err := endpoint.ParseURL(aux.URL)
	if err != nil {
		return endpoint.HTTPS{}, fmt.Errorf("keyless %s: %w", name, err)
	}
	return endpoint.HTTPS{Address: addr, Trust: t}, nil
}

// UnmarshalJSON implements json.Unmarshaler for Lane. It
// decodes the resolver, oidc, and keyless fields through their respective
// helpers, which dispatch the endpoint.Trust discriminator. All other
// fields fall through to the default decoder via the alias trick.
func (p *Lane) UnmarshalJSON(data []byte) error {
	type alias Lane
	aux := struct {
		*alias
		Resolver json.RawMessage `json:"resolver"`
		OIDC     json.RawMessage `json:"oidc"`
		Keyless  json.RawMessage `json:"keyless"`
	}{
		alias: (*alias)(p),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.Resolver) == 0 {
		return fmt.Errorf("lane: resolver required")
	}
	r, err := unmarshalDNSResolver(aux.Resolver)
	if err != nil {
		return fmt.Errorf("lane: %w", err)
	}
	p.Resolver = r
	if len(aux.Keyless) == 0 || string(aux.Keyless) == jsonNull {
		return fmt.Errorf("lane: keyless required")
	}
	k, kerr := unmarshalKeyless(aux.Keyless)
	if kerr != nil {
		return fmt.Errorf("lane: %w", kerr)
	}
	p.Keyless = k
	if len(aux.OIDC) == 0 || string(aux.OIDC) == jsonNull {
		return nil
	}
	oidc, err := unmarshalOIDCConfig(aux.OIDC)
	if err != nil {
		return fmt.Errorf("lane: %w", err)
	}
	p.OIDC = oidc
	return nil
}

// UnmarshalPeer decodes a peer JSON object using the type
// discriminator. Exported for callers in other packages
// (e.g. internal/deploy) that need the same dispatch logic
// when their containing struct declares peers as []lane.Peer.
func UnmarshalPeer(data []byte) (Peer, error) {
	return unmarshalPeer(data)
}
