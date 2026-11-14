package executor_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/schema"
	"github.com/istr/strike/test/crossval"
)

// crossvalDir is the on-disk path to cross-validation test vectors.
// Used only by updateVectorBlocks (writes); reads use crossval.FS.
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

// updateVectorBlocks reads a vector file, replaces the named top-level blocks
// with the provided values, and writes the whole vector back in the form
// canonicalVector renders. The values of the "inputs" block are never
// modified. A caller passes every block it replaces in one call: reads come
// from the embedded FS, so a second call would re-read the pre-update bytes
// and undo the first write.
func updateVectorBlocks(t *testing.T, subdir, name string, blocks map[string]any) {
	t.Helper()
	data, readErr := crossval.FS.ReadFile(subdir + "/" + name)
	if readErr != nil {
		t.Fatalf("read vector for update %s/%s: %v", subdir, name, readErr)
	}
	var raw map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(data, &raw); unmarshalErr != nil {
		t.Fatalf("unmarshal vector for update %s/%s: %v", subdir, name, unmarshalErr)
	}
	for key, value := range blocks {
		blockJSON, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatalf("marshal %s for update %s/%s: %v", key, subdir, name, marshalErr)
		}
		raw[key] = blockJSON
	}

	merged, mergeErr := json.Marshal(raw)
	if mergeErr != nil {
		t.Fatalf("marshal vector for update %s/%s: %v", subdir, name, mergeErr)
	}
	out, canonErr := canonicalVector(merged)
	if canonErr != nil {
		t.Fatalf("render vector for update %s/%s: %v", subdir, name, canonErr)
	}

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

// canonicalVector renders a vector in the one form every file under
// test/crossval is stored in: object keys sorted at every level, arrays in
// their given order, numbers in their literal form, no HTML escaping,
// two-space indentation, and one trailing newline. The form depends on the
// values alone, never on a Go struct's field order.
func canonicalVector(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if decodeErr := dec.Decode(&v); decodeErr != nil {
		return nil, decodeErr
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if encodeErr := enc.Encode(v); encodeErr != nil {
		return nil, encodeErr
	}
	return buf.Bytes(), nil
}

// TestCanonicalVector pins the canonical form on an input that violates
// every rule it orders: unsorted keys at two levels, an array that must keep
// its order, and characters an HTML-safe encoder would escape.
func TestCanonicalVector(t *testing.T) {
	got, err := canonicalVector([]byte(`{"b":[3,1],"a":{"d":"<&>","c":493}}`))
	if err != nil {
		t.Fatalf("canonicalVector: %v", err)
	}
	want := "{\n  \"a\": {\n    \"c\": 493,\n    \"d\": \"<&>\"\n  },\n  \"b\": [\n    3,\n    1\n  ]\n}\n"
	if string(got) != want {
		t.Errorf("canonical form:\n  got:  %q\n  want: %q", got, want)
	}
	if _, truncErr := canonicalVector([]byte(`{"a":`)); truncErr == nil {
		t.Error("canonicalVector accepted truncated JSON")
	}
}

// TestCrossvalVectorsCanonical asserts that every vector is stored in the
// form canonicalVector renders, so regenerating the vectors changes a file
// only where a value changes.
func TestCrossvalVectorsCanonical(t *testing.T) {
	files, err := fs.Glob(crossval.FS, "*/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no vector files found")
	}

	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			data, readErr := crossval.FS.ReadFile(f)
			if readErr != nil {
				t.Fatalf("read vector: %v", readErr)
			}
			canonical, canonErr := canonicalVector(data)
			if canonErr != nil {
				t.Fatalf("render canonical form: %v", canonErr)
			}
			if !bytes.Equal(data, canonical) {
				t.Error("vector is not in canonical form; see test/crossval/README.md")
			}
		})
	}
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

// boundaryToCUEType maps boundary names to their CUE definition paths.
var boundaryToCUEType = map[string]string{
	"AssembleImage":       "#AssembleVector",
	"SpecHash":            "#SpecHashVector",
	"ValidateAttestation": "#AttestationVector",
	"StateDigest":         "#StateDigestVector",
	"RenderKnownHosts":    "#RenderKnownHostsVector",
}

// TestCrossvalVectorsConformToSchema validates all vector files against
// the crossval CUE package loaded by internal/schema.
func TestCrossvalVectorsConformToSchema(t *testing.T) {
	files, err := fs.Glob(crossval.FS, "*/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no vector files found")
	}

	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			validateVectorAgainstCUE(t, f)
		})
	}
}

// validateVectorAgainstCUE validates a single vector file against the crossval
// schema. name is an embed-relative path like "spechash/foo.json".
func validateVectorAgainstCUE(t *testing.T, name string) {
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

	if err := schema.ValidateDef(schema.Crossval, cuePath, data); err != nil {
		t.Errorf("schema violation:\n%v", err)
	}
}

// assembleVector is the Go representation of an AssembleImage test vector.
type assembleVector struct {
	GoGGCRReference assembleGoGGCRReference `json:"go_ggcr_reference"`
	Boundary        string                  `json:"boundary"`
	Description     string                  `json:"description"`
	Inputs          assembleInputs          `json:"inputs"`
	Expected        assembleExpected        `json:"expected"`
}

type assembleFileEntry struct {
	ContentBase64 string `json:"content_base64"`
	Mode          int    `json:"mode"`
}

// assembleBase describes the base image the boundary starts from in wire
// terms, so an implementation constructs it rather than naming a library
// artifact.
type assembleBase struct {
	ManifestMediaType string   `json:"manifest_media_type"`
	ConfigMediaType   string   `json:"config_media_type"`
	ConfigJSONBase64  string   `json:"config_json_base64"`
	Layers            []string `json:"layers"`
}

type assembleInputs struct {
	Spec  lane.PackSpec                `json:"spec"`
	Files map[string]assembleFileEntry `json:"files"`
	Base  assembleBase                 `json:"base"`
}

// assembleExpected is what every conforming implementation reproduces.
type assembleExpected struct {
	ConfigJSONBase64 string   `json:"config_json_base64"`
	DiffIDs          []string `json:"diff_ids"`
}

// assembleGoGGCRReference is not normative: these digests are a property of the
// reference implementation, not of the boundary. The layer digest inside the
// manifest covers a compressed blob and DEFLATE output is not specified by
// compression level (ADR-046).
type assembleGoGGCRReference struct {
	ManifestDigest string `json:"manifest_digest"`
	ConfigDigest   string `json:"config_digest"`
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
	InputHashes  map[string]primitive.Digest `json:"input_hashes"`
	SourceHashes map[string]primitive.Digest `json:"source_hashes"`
	ImageDigest  primitive.Digest            `json:"image_digest"`
	Step         specHashStep                `json:"step"`
}

type specHashExpected struct {
	Hash primitive.Digest `json:"hash"`
}

// renderKnownHostsVector is the Go representation of a RenderKnownHosts test
// vector. It lives here with the other vector representations rather than
// beside its runner: the two are the same kind of thing, and splitting them
// once already hid the runner from a reader looking for it.
type renderKnownHostsVector struct {
	Expected    renderKnownHostsExpected `json:"expected"`
	Boundary    string                   `json:"boundary"`
	Description string                   `json:"description"`
	Inputs      renderKnownHostsInputs   `json:"inputs"`
}

// renderKnownHostsInputs carries both inputs of the boundary. Peers stay raw
// because endpoint.UnmarshalEndpoint is the discriminated decoder for the
// endpoint disjunction.
type renderKnownHostsInputs struct {
	FrontKey endpoint.HostKey  `json:"front_key"`
	Peers    []json.RawMessage `json:"peers"`
}

type renderKnownHostsExpected struct {
	ContentBase64 string `json:"content_base64"`
}
