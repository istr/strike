package lane

// DeployMethod accessor helpers -- the generated type is map[string]any
// because CUE unions produce open structs.

// mval safely extracts a typed value from a map[string]any.
func mval[T any](m map[string]any, key string) (T, bool) {
	v, ok := m[key].(T)
	return v, ok
}

// Type returns the deploy method type ("registry", "kubernetes", "custom").
func (m DeployMethod) Type() string { v, _ := mval[string](m, "type"); return v }

// Namespace returns the target Kubernetes namespace.
func (m DeployMethod) Namespace() string { v, _ := mval[string](m, "namespace"); return v }

// Strategy returns the Kubernetes apply strategy.
func (m DeployMethod) Strategy() string { v, _ := mval[string](m, "strategy"); return v }

// Source returns the source image reference for registry deploys.
func (m DeployMethod) Source() string { v, _ := mval[string](m, "source"); return v }

// MethodTarget returns the target image reference for registry deploys.
func (m DeployMethod) MethodTarget() string { v, _ := mval[string](m, "target"); return v }

// Image returns the container image for custom deploys.
func (m DeployMethod) Image() string { v, _ := mval[string](m, "image"); return v }

// Kubeconfig returns the kubeconfig path.
func (m DeployMethod) Kubeconfig() string { v, _ := mval[string](m, "kubeconfig"); return v }

// Entrypoint returns the entrypoint override for custom deploys.
func (m DeployMethod) Entrypoint() []string {
	sl, ok := mval[[]any](m, "entrypoint")
	if !ok {
		return nil
	}
	out := make([]string, len(sl))
	for i, s := range sl {
		str, ok := s.(string)
		if ok {
			out[i] = str
		}
	}
	return out
}

// Args returns the command arguments for custom deploys.
func (m DeployMethod) Args() []string {
	sl, ok := mval[[]any](m, "args")
	if !ok {
		return nil
	}
	out := make([]string, len(sl))
	for i, s := range sl {
		str, ok := s.(string)
		if ok {
			out[i] = str
		}
	}
	return out
}

// Env returns the environment variables for custom deploys.
func (m DeployMethod) Env() map[string]string {
	mp, ok := mval[map[string]any](m, "env")
	if !ok {
		return nil
	}
	out := make(map[string]string, len(mp))
	for k, v := range mp {
		str, ok := v.(string)
		if ok {
			out[k] = str
		}
	}
	return out
}
