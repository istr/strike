package lane

import (
	"encoding/json"
	"fmt"
)

// UnmarshalJSON implements json.Unmarshaler for DeploySpec. It reads
// the method.type discriminator and unmarshals method into the
// appropriate concrete branch type (DeployKubernetes, DeployRegistry,
// DeployCustom). An unknown or missing discriminator is a parse-time
// error -- validation thus catches typos at `strike validate` rather
// than at `strike run`.
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
		Type string `json:"type"`
	}
	if err := json.Unmarshal(aux.Method, &probe); err != nil {
		return fmt.Errorf("deploy method: %w", err)
	}

	switch probe.Type {
	case "kubernetes":
		var m DeployKubernetes
		if err := json.Unmarshal(aux.Method, &m); err != nil {
			return fmt.Errorf("decode kubernetes deploy method: %w", err)
		}
		s.Method = m
	case "registry":
		var m DeployRegistry
		if err := json.Unmarshal(aux.Method, &m); err != nil {
			return fmt.Errorf("decode registry deploy method: %w", err)
		}
		s.Method = m
	case "custom":
		var m DeployCustom
		if err := json.Unmarshal(aux.Method, &m); err != nil {
			return fmt.Errorf("decode custom deploy method: %w", err)
		}
		s.Method = m
	case "":
		return fmt.Errorf("deploy method missing type discriminator")
	default:
		return fmt.Errorf("unknown deploy method type %q", probe.Type)
	}

	return nil
}
