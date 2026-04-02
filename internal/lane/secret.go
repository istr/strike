package lane

import (
	"fmt"
	"io"
	"os"
	"strings"
)

func readFileSecret(root *os.Root, path string) (val string, err error) {
	f, err := root.Open(path)
	if err != nil {
		return "", fmt.Errorf("secret file %q: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(data), "\n"), nil
}

// ReadSecret reads a secret value from the source URI (env:// or file://).
// File secrets are resolved through the lane root scope.
func ReadSecret(source SecretSource, root *os.Root) (string, error) {
	s := string(source)
	switch {
	case len(s) > 6 && s[:6] == "env://":
		val, ok := os.LookupEnv(s[6:])
		if !ok {
			return "", fmt.Errorf("env variable %q not set", s[6:])
		}
		return val, nil
	case len(s) > 7 && s[:7] == "file://":
		return readFileSecret(root, s[7:])
	default:
		return "", fmt.Errorf("unknown secret source: %q (supported: env://, file://)", s)
	}
}

// ResolveSecrets resolves all secret references to their values.
// File secrets are resolved through the lane root scope.
func ResolveSecrets(refs []SecretRef, sources map[string]SecretSource, root *os.Root) (map[string]string, error) {
	result := map[string]string{}
	for _, ref := range refs {
		source, ok := sources[ref.Name]
		if !ok {
			return nil, fmt.Errorf("secret %q not defined in lane.secrets", ref.Name)
		}
		val, err := ReadSecret(source, root)
		if err != nil {
			return nil, fmt.Errorf("secret %q: %w", ref.Name, err)
		}
		result[ref.Env] = val
	}
	return result, nil
}
