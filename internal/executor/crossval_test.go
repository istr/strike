package executor_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/encoding/json"
)

// crossvalDir is the path to cross-validation test vectors.
// Relative to the executor package test directory.
const crossvalDir = "../../test/crossval"

// loadVector reads and unmarshals a cross-validation vector file.
func loadVector[T any](t *testing.T, subdir, name string) T {
	t.Helper()
	path := filepath.Join(crossvalDir, subdir, name)
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a hardcoded test constant, not user input
	if err != nil {
		t.Fatalf("load vector %s/%s: %v", subdir, name, err)
	}
	var v T
	if unmarshalErr := json.Unmarshal(data, &v); unmarshalErr != nil {
		t.Fatalf("unmarshal vector %s/%s: %v", subdir, name, unmarshalErr)
	}
	return v
}

// updateVectorExpected reads a vector file, replaces its "expected" block
// with the provided value, and writes it back. The "inputs" block is never
// modified.
func updateVectorExpected(t *testing.T, subdir, name string, expected any) {
	t.Helper()
	path := filepath.Join(crossvalDir, subdir, name)
	data, readErr := os.ReadFile(path) //nolint:gosec // G304: path is a hardcoded test constant, not user input
	if readErr != nil {
		t.Fatalf("read vector for update %s/%s: %v", subdir, name, readErr)
	}
	var raw map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(data, &raw); unmarshalErr != nil {
		t.Fatalf("unmarshal vector for update %s/%s: %v", subdir, name, unmarshalErr)
	}
	expJSON, marshalErr := json.Marshal(expected)
	if marshalErr != nil {
		t.Fatalf("marshal expected for update %s/%s: %v", subdir, name, marshalErr)
	}
	raw["expected"] = expJSON

	out, indentErr := json.MarshalIndent(raw, "", "  ")
	if indentErr != nil {
		t.Fatalf("marshal vector for update %s/%s: %v", subdir, name, indentErr)
	}
	out = append(out, '\n')
	if writeErr := os.WriteFile(path, out, 0o600); writeErr != nil {
		t.Fatalf("write vector %s/%s: %v", subdir, name, writeErr)
	}
	t.Logf("updated vector: %s/%s", subdir, name)
}

// decodeBase64 decodes a base64 string or fails the test.
func decodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return data
}

// cueSchemaPath is the path to the crossval CUE schema.
const cueSchemaPath = "../../specs/crossval.cue"

// boundaryToCUEType maps boundary names to their CUE definition paths.
var boundaryToCUEType = map[string]string{
	"AssembleImage":       "#AssembleVector",
	"SpecHash":            "#SpecHashVector",
	"SignManifest":        "#SignVector",
	"SignAttestation":     "#SignAttestationVector",
	"ValidateAttestation": "#AttestationVector",
}

// TestCrossvalVectorsConformToSchema validates all vector files against
// the CUE schema in specs/crossval.cue.
func TestCrossvalVectorsConformToSchema(t *testing.T) {
	schemaData, err := os.ReadFile(cueSchemaPath)
	if err != nil {
		t.Fatalf("read CUE schema: %v", err)
	}

	ctx := cuecontext.New()
	compiled := ctx.CompileBytes(schemaData)
	if compiled.Err() != nil {
		t.Fatalf("compile CUE schema: %v", compiled.Err())
	}

	files, err := filepath.Glob(filepath.Join(crossvalDir, "*", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no vector files found")
	}

	for _, f := range files {
		rel, relErr := filepath.Rel(crossvalDir, f)
		if relErr != nil {
			t.Fatalf("filepath.Rel: %v", relErr)
		}
		t.Run(rel, func(t *testing.T) {
			validateVectorAgainstCUE(t, ctx, compiled, f)
		})
	}
}

// validateVectorAgainstCUE validates a single vector file against the compiled CUE schema.
func validateVectorAgainstCUE(t *testing.T, ctx *cue.Context, compiled cue.Value, path string) {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a hardcoded test constant, not user input
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}

	var envelope struct {
		Boundary string `json:"boundary"`
	}
	if unmarshalErr := json.Unmarshal(data, &envelope); unmarshalErr != nil {
		t.Fatalf("unmarshal boundary: %v", unmarshalErr)
	}

	cuePath, ok := boundaryToCUEType[envelope.Boundary]
	if !ok {
		t.Fatalf("unknown boundary %q", envelope.Boundary)
	}

	schema := compiled.LookupPath(cue.ParsePath(cuePath))
	if schema.Err() != nil {
		t.Fatalf("lookup %s: %v", cuePath, schema.Err())
	}

	expr, err := cuejson.Extract(filepath.Base(path), data)
	if err != nil {
		t.Fatalf("extract JSON: %v", err)
	}

	unified := schema.Unify(ctx.BuildExpr(expr))
	if err := unified.Validate(cue.Concrete(true)); err != nil {
		t.Errorf("schema violation:\n%v", err)
	}
}

// assembleVector is the Go representation of an AssembleImage test vector.
type assembleVector struct {
	Inputs      assembleInputs   `json:"inputs"`
	Boundary    string           `json:"boundary"`
	Description string           `json:"description"`
	Expected    assembleExpected `json:"expected"`
}

type assembleFileEntry struct {
	ContentBase64 string `json:"content_base64"`
	Mode          int    `json:"mode"`
}

type assembleInputs struct {
	Files map[string]assembleFileEntry `json:"files"`
	Base  string                       `json:"base"`
	Spec  json.RawMessage              `json:"spec"`
}

type assembleExpected struct {
	ManifestDigest string `json:"manifest_digest"`
	ConfigDigest   string `json:"config_digest"`
	LayerCount     int    `json:"layer_count"`
}

type specHashVector struct {
	Boundary    string           `json:"boundary"`
	Description string           `json:"description"`
	Expected    specHashExpected `json:"expected"`
	Inputs      specHashInputs   `json:"inputs"`
}

type specHashStep struct {
	Env  map[string]string `json:"env"`
	Args []string          `json:"args"`
}

type specHashInputs struct {
	InputHashes  map[string]string `json:"input_hashes"`
	SourceHashes map[string]string `json:"source_hashes"`
	ImageDigest  string            `json:"image_digest"`
	Step         specHashStep      `json:"step"`
}

type specHashExpected struct {
	Hash string `json:"hash"`
}

type signVector struct {
	Inputs      signInputs   `json:"inputs"`
	Expected    signExpected `json:"expected"`
	Boundary    string       `json:"boundary"`
	Description string       `json:"description"`
}

type signInputs struct {
	Password       *string `json:"password"`
	ManifestDigest string  `json:"manifest_digest"`
	KeyPEM         string  `json:"key_pem,omitempty"`
}

type signVerify struct {
	Algorithm          string `json:"algorithm"`
	PublicKeyDERBase64 string `json:"public_key_der_base64,omitempty"`
}

type signExpected struct {
	Verify  signVerify `json:"verify"`
	Payload string     `json:"payload"`
}
