package lane

import (
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// SecretString holds a sensitive value that is redacted in all string
// representations. This prevents accidental leakage through logging,
// fmt.Printf, JSON serialization, and error messages.
type SecretString struct {
	value string
}

// Compile-time interface satisfaction checks. These ensure SecretString
// always implements the interfaces that prevent accidental leakage.
var (
	_ fmt.Stringer           = SecretString{}
	_ fmt.GoStringer         = SecretString{}
	_ encoding.TextMarshaler = SecretString{}
	_ json.Marshaler         = SecretString{}
)

// NewSecretString wraps a plaintext value.
func NewSecretString(value string) SecretString {
	return SecretString{value: value}
}

// Expose returns the plaintext value. Call only when passing to a container
// environment variable or a cryptographic operation.
func (s SecretString) Expose() string {
	return s.value
}

// String implements fmt.Stringer. Always returns [REDACTED].
func (s SecretString) String() string { return "[REDACTED]" }

// GoString implements fmt.GoStringer. Always returns [REDACTED].
func (s SecretString) GoString() string { return "[REDACTED]" }

// MarshalText implements encoding.TextMarshaler. Always returns [REDACTED].
func (s SecretString) MarshalText() ([]byte, error) {
	return []byte("[REDACTED]"), nil
}

// MarshalJSON implements json.Marshaler. Always returns "[REDACTED]".
func (s SecretString) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

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
func ReadSecret(source SecretSource, root *os.Root) (SecretString, error) {
	s := string(source)
	switch {
	case len(s) > 6 && s[:6] == "env://":
		val, ok := os.LookupEnv(s[6:])
		if !ok {
			return SecretString{}, fmt.Errorf("env variable %q not set", s[6:])
		}
		return NewSecretString(val), nil
	case len(s) > 7 && s[:7] == "file://":
		val, err := readFileSecret(root, s[7:])
		if err != nil {
			return SecretString{}, err
		}
		return NewSecretString(val), nil
	default:
		return SecretString{}, fmt.Errorf("unknown secret source: %q (supported: env://, file://)", s)
	}
}

// ResolveSecrets resolves all secret references to their values.
// File secrets are resolved through the lane root scope.
func ResolveSecrets(refs []SecretRef, sources map[string]SecretSource, root *os.Root) (map[string]SecretString, error) {
	result := map[string]SecretString{}
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
