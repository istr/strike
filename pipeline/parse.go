package pipeline

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

// Parse reads a pipeline YAML file, validates it against the embedded CUE schema,
// and returns a typed Pipeline instance.
func Parse(path string) (*Pipeline, error) {
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

    // Deserialize into typed Pipeline struct
    var p Pipeline
    if err := yaml.Unmarshal(raw, &p); err != nil {
        return nil, fmt.Errorf("deserialize: %w", err)
    }

    // Validate: exactly one of image or image_from per step
    for _, s := range p.Steps {
        hasImage := s.Image != ""
        hasImageFrom := s.ImageFrom != nil
        if hasImage == hasImageFrom {
            return nil, fmt.Errorf("step %q: exactly one of image or image_from required", s.Name)
        }
    }

    return &p, nil
}

func validate(data []byte) error {
    ctx := cuecontext.New()

    compiledSchema := ctx.CompileString(schema).
        LookupPath(cue.ParsePath("#Pipeline"))

    expr, err := cuejson.Extract("pipeline.yaml", data)
    if err != nil {
        return err
    }

    unified := compiledSchema.Unify(ctx.BuildExpr(expr))
    return unified.Validate(cue.Concrete(true))
}
