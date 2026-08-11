package lane

import (
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
)

// UnmarshalJSON implements json.Unmarshaler for DeploySpec. It reads
// the method.type discriminator and unmarshals method into the
// appropriate concrete branch type (DeployKubernetes, DeployRegistry).
// An unknown or missing discriminator is a parse-time error --
// validation thus catches typos at `strike validate` rather than at
// `strike run`.
func (s *DeploySpec) UnmarshalJSON(data []byte) error {
	type alias DeploySpec // break the recursion
	aux := struct {
		*alias
		Method json.RawMessage `json:"method"`
	}{
		alias: (*alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if len(aux.Method) == 0 {
		return fmt.Errorf("deploy method missing")
	}

	var probe struct {
		Type DeployMethodType `json:"type"`
	}
	if err := json.Unmarshal(aux.Method, &probe); err != nil {
		return fmt.Errorf("deploy method: %w", err)
	}

	switch probe.Type {
	case DeployMethodTypeKubernetes:
		var m DeployKubernetes
		if err := json.Unmarshal(aux.Method, &m); err != nil {
			return fmt.Errorf("decode kubernetes deploy method: %w", err)
		}
		s.Method = m
	case DeployMethodTypeRegistry:
		var m DeployRegistry
		if err := json.Unmarshal(aux.Method, &m); err != nil {
			return fmt.Errorf("decode registry deploy method: %w", err)
		}
		s.Method = m
	case "":
		return fmt.Errorf("deploy method missing type discriminator")
	default:
		return fmt.Errorf("unknown deploy method type %q", probe.Type)
	}

	return nil
}

// UnmarshalJSON decodes the registry push target: the packed authority host
// projects into endpoint.Address and the trust discriminator dispatches into
// its endpoint.Trust arm, mirroring the resolver decode
// (unmarshalDNSResolver). The https carriage type is fixed and set here, not
// read from the wire.
func (t *DeployRegistryTarget) UnmarshalJSON(data []byte) error {
	var aux struct {
		Host  string            `json:"host"`
		Name  primitive.OCIName `json:"name"`
		Trust json.RawMessage   `json:"trust"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("decode registry target: %w", err)
	}
	if len(aux.Trust) == 0 {
		return fmt.Errorf("registry target: trust required")
	}
	tr, err := unmarshalTLSTrust(aux.Trust)
	if err != nil {
		return fmt.Errorf("registry target: %w", err)
	}
	addr, err := endpoint.ParseAuthority(aux.Host)
	if err != nil {
		return fmt.Errorf("registry target host: %w", err)
	}
	t.Type = "https"
	t.Address = addr
	t.Trust = tr
	t.Name = aux.Name
	return nil
}
