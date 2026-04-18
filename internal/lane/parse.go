package lane

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/encoding/json"
	"github.com/istr/strike/specs"
	"gopkg.in/yaml.v3"
)

// ParseDuration converts a lane duration string ("30s", "5m", "1h") to
// time.Duration. Returns defaultVal if d is empty.
func ParseDuration(d Duration, defaultVal time.Duration) (time.Duration, error) {
	if d == "" {
		return defaultVal, nil
	}
	return time.ParseDuration(string(d))
}

var schema = specs.LaneSchema

// Parse reads a lane YAML file, validates it against the embedded CUE schema,
// and returns a typed Lane instance.
func Parse(path string) (*Lane, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: lane file path from CLI argument
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// YAML to generic map (for CUE validation)
	var asMap any
	if yamlErr := yaml.Unmarshal(raw, &asMap); yamlErr != nil {
		return nil, fmt.Errorf("yaml parse: %w", yamlErr)
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

	if err := ValidatePaths(&p); err != nil {
		return nil, err
	}

	return &p, nil
}

// ValidatePaths rejects unsafe paths in sources, outputs, and pack dests.
// Defense-in-depth -- os.Root enforces at runtime, but rejecting early
// produces better error messages.
//
// sources[].path is a host path relative to the lane root -- it must
// be local (filepath.IsLocal) to prevent escape from the lane scope.
//
// outputs[].path and pack.files[].dest are container-internal paths
// (e.g., /src/node_modules, /usr/bin/strike). They must be absolute
// and canonical (no ".." components).
func ValidatePaths(p *Lane) error {
	for _, s := range p.Steps {
		if err := validateStepPaths(s); err != nil {
			return err
		}
	}
	return nil
}

// validateStepPaths checks one step's source, output, and pack-dest paths.
func validateStepPaths(s Step) error {
	for _, src := range s.Sources {
		if !filepath.IsLocal(src.Path) {
			return fmt.Errorf("step %q: source path %q must be relative to lane root", s.Name, src.Path)
		}
	}
	for _, out := range s.Outputs {
		if !filepath.IsAbs(out.Path) {
			return fmt.Errorf("step %q: output path %q must be an absolute container path", s.Name, out.Path)
		}
		if filepath.Clean(out.Path) != out.Path {
			return fmt.Errorf("step %q: output path %q is not canonical", s.Name, out.Path)
		}
	}
	if s.Pack != nil {
		for _, f := range s.Pack.Files {
			if !filepath.IsAbs(f.Dest) {
				return fmt.Errorf("step %q: pack dest %q must be an absolute container path", s.Name, f.Dest)
			}
			if filepath.Clean(f.Dest) != f.Dest {
				return fmt.Errorf("step %q: pack dest %q is not canonical", s.Name, f.Dest)
			}
		}
	}
	return nil
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
