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

// Parse reads pipeline.yaml, validates against the embedded CUE schema
// and returns a typed pipeline instance.
func Parse(path string) (*Pipeline, error) {
    raw, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("lesen: %w", err)
    }

    // YAML to generich map (for CUE validation)
    var asMap any
    if err := yaml.Unmarshal(raw, &asMap); err != nil {
        return nil, fmt.Errorf("yaml parse: %w", err)
    }

    // convert to JSON (CUE is a superset of JSON)
    asJSON, err := json.Marshal(asMap)
    if err != nil {
        return nil, fmt.Errorf("json marshal: %w", err)
    }

    // CUE-Validierung gegen eingebettetes Schema
    if err := validate(asJSON); err != nil {
        return nil, fmt.Errorf("validierung:\n%w", err)
    }

    // In typisierte Pipeline-Struct deserialisieren
    var p Pipeline
    if err := yaml.Unmarshal(raw, &p); err != nil {
        return nil, fmt.Errorf("deserialize: %w", err)
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
