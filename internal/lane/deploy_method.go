package lane

// DeployMethod accessor helpers -- the generated type is map[string]any
// because CUE unions produce open structs.

// Type returns the deploy method type ("registry", "kubernetes", "custom").
func (m DeployMethod) Type() string { return mstr(m, "type") }

// Namespace returns the target Kubernetes namespace.
func (m DeployMethod) Namespace() string { return mstr(m, "namespace") }

// Strategy returns the Kubernetes apply strategy.
func (m DeployMethod) Strategy() string { return mstr(m, "strategy") }

// Source returns the source image reference for registry deploys.
func (m DeployMethod) Source() string { return mstr(m, "source") }

// MethodTarget returns the target image reference for registry deploys.
func (m DeployMethod) MethodTarget() string { return mstr(m, "target") }

// Image returns the container image for custom deploys.
func (m DeployMethod) Image() string { return mstr(m, "image") }

// Kubeconfig returns the kubeconfig path.
func (m DeployMethod) Kubeconfig() string { return mstr(m, "kubeconfig") }

// Args returns the command arguments for custom deploys.
func (m DeployMethod) Args() []string {
	v, ok := m["args"]
	if !ok {
		return nil
	}
	if sl, ok := v.([]any); ok {
		out := make([]string, len(sl))
		for i, s := range sl {
			str, ok := s.(string)
			if ok {
				out[i] = str
			}
		}
		return out
	}
	return nil
}

// Env returns the environment variables for custom deploys.
func (m DeployMethod) Env() map[string]string {
	v, ok := m["env"]
	if !ok {
		return nil
	}
	if mp, ok := v.(map[string]any); ok {
		out := make(map[string]string, len(mp))
		for k, v := range mp {
			str, ok := v.(string)
			if ok {
				out[k] = str
			}
		}
		return out
	}
	return nil
}

func mstr(m map[string]any, key string) string {
	v, ok := m[key].(string)
	if !ok {
		return ""
	}
	return v
}
