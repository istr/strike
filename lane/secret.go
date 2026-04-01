package lane

import (
	"fmt"
	"os"
)

// ReadSecret reads a secret value from the source URI (env:// or file://).
func ReadSecret(source SecretSource) (string, error) {
	s := string(source)
	switch {
	case len(s) > 6 && s[:6] == "env://":
		val, ok := os.LookupEnv(s[6:])
		if !ok {
			return "", fmt.Errorf("env variable %q not set", s[6:])
		}
		return val, nil
	case len(s) > 7 && s[:7] == "file://":
		data, err := os.ReadFile(s[7:])
		return string(data), err
	default:
		return "", fmt.Errorf("unknown secret source: %q (supported: env://, file://)", s)
	}
}

// ResolveSecrets resolves all secret references to their values.
func ResolveSecrets(refs []SecretRef, sources map[string]SecretSource) (map[string]string, error) {
	result := map[string]string{}
	for _, ref := range refs {
		source, ok := sources[ref.Name]
		if !ok {
			return nil, fmt.Errorf("secret %q not defined in lane.secrets", ref.Name)
		}
		val, err := ReadSecret(source)
		if err != nil {
			return nil, fmt.Errorf("secret %q: %w", ref.Name, err)
		}
		result[ref.Env] = val
	}
	return result, nil
}
