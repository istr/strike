package lane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/schema"

	"gopkg.in/yaml.v3"
)

// ParseDuration converts a lane duration pointer to clock.Duration.
// Returns defaultVal if d is nil.
func ParseDuration(d *primitive.Duration, defaultVal clock.Duration) (clock.Duration, error) {
	if d == nil {
		return defaultVal, nil
	}
	s := string(*d)
	return clock.ParseDuration(s)
}

// IndexSteps builds the step-id lookup index for a lane and rejects a
// duplicate step id. The index maps each step id to a pointer into
// p.Steps, so callers must not mutate p.Steps after indexing. Parse
// returns it alongside the Lane; Build consumes it as its private step
// reference.
func IndexSteps(p *Lane) (map[primitive.Identifier]*Step, error) {
	index := make(map[primitive.Identifier]*Step, len(p.Steps))
	for i := range p.Steps {
		s := &p.Steps[i]
		if _, exists := index[s.ID]; exists {
			return nil, fmt.Errorf("duplicate step name: %q", s.ID)
		}
		index[s.ID] = s
	}
	return index, nil
}

// Parse reads a lane YAML file, validates it against the embedded CUE schema,
// and returns a typed Lane instance together with the raw sha256 digest of
// the file bytes. Hash and parse consume the same single read, so the digest
// is bound to exactly the bytes the Lane was built from; it is carried into
// the sealed attestation as lane_digest.
func Parse(fp FilePath) (*Lane, map[primitive.Identifier]*Step, primitive.Digest, error) {
	raw, err := fp.Read()
	if err != nil {
		return nil, nil, "", fmt.Errorf("read: %w", err)
	}
	// The input is "sha256:" followed by 64 lowercase hex by construction, so it
	// satisfies #Digest directly; it is bound to exactly the bytes the Lane was
	// built from and carried into the sealed attestation as lane_digest.
	sum := sha256.Sum256(raw)
	dg := primitive.DigestFromHex(hex.EncodeToString(sum[:]))

	// YAML to generic map (for CUE validation)
	var asMap any
	if yamlErr := yaml.Unmarshal(raw, &asMap); yamlErr != nil {
		return nil, nil, "", fmt.Errorf("yaml parse: %w", yamlErr)
	}

	// Convert to JSON (CUE is a superset of JSON)
	asJSON, err := json.Marshal(asMap)
	if err != nil {
		return nil, nil, "", fmt.Errorf("json marshal: %w", err)
	}

	// Validate against embedded CUE schema
	if err := schema.ValidateLaneJSON(asJSON); err != nil {
		return nil, nil, "", fmt.Errorf("validation:\n%w", err)
	}

	// Deserialize from JSON into typed Lane struct.
	// Using JSON (not YAML) because gengotypes only emits json struct tags.
	var p Lane
	if err := json.Unmarshal(asJSON, &p); err != nil {
		return nil, nil, "", fmt.Errorf("deserialize: %w", err)
	}

	index, idxErr := IndexSteps(&p)
	if idxErr != nil {
		return nil, nil, "", idxErr
	}

	return &p, index, dg, nil
}
