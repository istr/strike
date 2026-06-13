package executor_test

import (
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/test/crossval"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/encoding/json"
)

// crossvalDir is the on-disk path to cross-validation test vectors.
// Used only by updateVectorExpected (writes); reads use crossval.FS.
const crossvalDir = "../../test/crossval"

// loadVector reads and unmarshals a cross-validation vector file from the
// embedded crossval.FS.
func loadVector[T any](t *testing.T, subdir, name string) T {
	t.Helper()
	data, err := crossval.FS.ReadFile(subdir + "/" + name)
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
	data, readErr := crossval.FS.ReadFile(subdir + "/" + name)
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

	root, rootErr := os.OpenRoot(filepath.Join(crossvalDir, subdir))
	if rootErr != nil {
		t.Fatalf("open root for update %s/%s: %v", subdir, name, rootErr)
	}
	defer closer.Warn(root, "crossval update root")
	f, createErr := root.Create(name)
	if createErr != nil {
		t.Fatalf("create vector %s/%s: %v", subdir, name, createErr)
	}
	if _, writeErr := f.Write(out); writeErr != nil {
		closer.Warn(f, "crossval write error cleanup")
		t.Fatalf("write vector %s/%s: %v", subdir, name, writeErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		t.Fatalf("close vector %s/%s: %v", subdir, name, closeErr)
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
	"ValidateAttestation": "#AttestationVector",
	"StateDigest":         "#StateDigestVector",
	"RenderKnownHosts":    "#RenderKnownHostsVector",
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

	files, err := fs.Glob(crossval.FS, "*/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no vector files found")
	}

	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			validateVectorAgainstCUE(t, ctx, compiled, f)
		})
	}
}

// validateVectorAgainstCUE validates a single vector file against the compiled CUE schema.
// name is an embed-relative path like "spechash/foo.json".
func validateVectorAgainstCUE(t *testing.T, ctx *cue.Context, compiled cue.Value, name string) {
	t.Helper()

	data, err := crossval.FS.ReadFile(name)
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

	expr, err := cuejson.Extract(filepath.Base(name), data)
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
