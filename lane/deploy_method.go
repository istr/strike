package lane

// DeployMethod accessor helpers — the generated type is map[string]any
// because CUE unions produce open structs.

func (m DeployMethod) Type() string      { return mstr(m, "type") }
func (m DeployMethod) Namespace() string { return mstr(m, "namespace") }
func (m DeployMethod) Strategy() string  { return mstr(m, "strategy") }
func (m DeployMethod) Source() string    { return mstr(m, "source") }
func (m DeployMethod) MethodTarget() string { return mstr(m, "target") }
func (m DeployMethod) Image() string     { return mstr(m, "image") }

func (m DeployMethod) Args() []string {
	v, ok := m["args"]
	if !ok {
		return nil
	}
	if sl, ok := v.([]any); ok {
		out := make([]string, len(sl))
		for i, s := range sl {
			out[i], _ = s.(string)
		}
		return out
	}
	return nil
}

func (m DeployMethod) Env() map[string]string {
	v, ok := m["env"]
	if !ok {
		return nil
	}
	if mp, ok := v.(map[string]any); ok {
		out := make(map[string]string, len(mp))
		for k, v := range mp {
			out[k], _ = v.(string)
		}
		return out
	}
	return nil
}

func mstr(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}
