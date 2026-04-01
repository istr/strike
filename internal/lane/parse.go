package lane

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/encoding/json"
	"gopkg.in/yaml.v3"
)

//go:embed schema.cue
var schema string

// Parse reads a lane YAML file, validates it against the embedded CUE schema,
// and returns a typed Lane instance.
func Parse(path string) (*Lane, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// YAML to generic map (for CUE validation)
	var asMap any
	if err := yaml.Unmarshal(raw, &asMap); err != nil {
		return nil, fmt.Errorf("yaml parse: %w", err)
	}

	// Convert to JSON (CUE is a superset of JSON)
	asJSON, err := json.Marshal(asMap)
	if err != nil {
		return nil, fmt.Errorf("json marshal: %w", err)
	}

	// Validate against embedded CUE schema
	if err := validate(asJSON); err != nil {
		return nil, fmt.Errorf("validation:\n%w", err)
	}

	// Deserialize from JSON into typed Lane struct.
	// Using JSON (not YAML) because gengotypes only emits json struct tags.
	var p Lane
	if err := json.Unmarshal(asJSON, &p); err != nil {
		return nil, fmt.Errorf("deserialize: %w", err)
	}

	// Validate: exactly one of image, image_from, pack, or deploy per step
	for _, s := range p.Steps {
		count := 0
		if s.Image != "" {
			count++
		}
		if s.ImageFrom != nil {
			count++
		}
		if s.Pack != nil {
			count++
		}
		if s.Deploy != nil {
			count++
		}
		if count != 1 {
			return nil, fmt.Errorf(
				"step %q: exactly one of image, image_from, pack, or deploy required", s.Name)
		}
	}

	return &p, nil
}

func validate(data []byte) error {
	ctx := cuecontext.New()

	compiledSchema := ctx.CompileString(schema).
		LookupPath(cue.ParsePath("#Lane"))

	expr, err := cuejson.Extract("lane.yaml", data)
	if err != nil {
		return err
	}

	unified := compiledSchema.Unify(ctx.BuildExpr(expr))
	return unified.Validate(cue.Concrete(true))
}
