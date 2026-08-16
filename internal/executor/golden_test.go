package executor_test

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"flag"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/test/crossval"
)

var update = flag.Bool("update", false, "update cross-validation vector expected fields")

// toDigestMap converts a map[string]string (from JSON vectors) to map[string]primitive.Digest.
func toDigestMap(m map[string]string) map[string]primitive.Digest {
	out := make(map[string]primitive.Digest, len(m))
	for k, v := range m {
		out[k] = primitive.Digest(v)
	}
	return out
}

// canonicalFileTar builds the canonical content tar for a single regular
// file landing at dest: the parent directories of dest, then the file at
// dest without its leading slash, ownership and mtime zero, entries
// name-sorted -- the shape registry.PackTarFromImage emits for a
// single-file selection.
func canonicalFileTar(t *testing.T, dest string, content []byte, mode int64) []byte {
	t.Helper()
	name := dest[1:]
	names := []string{name}
	for d := path.Dir(name); d != "."; d = path.Dir(d) {
		names = append(names, d)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		// Uid, Gid, ModTime intentionally zero for determinism.
		hdr := &tar.Header{Name: n + "/", Mode: 0o755, Typeflag: tar.TypeDir}
		if n == name {
			hdr = &tar.Header{Name: n, Mode: mode, Typeflag: tar.TypeReg, Size: int64(len(content))}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %s: %v", n, err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write(content); err != nil {
				t.Fatalf("write tar content %s: %v", n, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// vectorInputTars builds one canonical content tar per vector file entry,
// keyed by Dest (matching the contract of addFileLayers).
func vectorInputTars(t *testing.T, specFiles []lane.PackFile, vecFiles map[string]assembleFileEntry) map[string][]byte {
	t.Helper()
	fromToDest := make(map[string]string, len(specFiles))
	for _, pf := range specFiles {
		fromToDest[string(pf.From.Step)+"."+string(pf.From.Output)] = pf.Dest.String()
	}
	inputTars := make(map[string][]byte, len(vecFiles))
	for ref, f := range vecFiles {
		content := decodeBase64(t, f.ContentBase64)
		if f.Mode < 0 || f.Mode > 0o7777 {
			t.Fatalf("test file %s: invalid mode %d", ref, f.Mode)
		}
		dest, ok := fromToDest[ref]
		if !ok {
			t.Fatalf("vector file %q not found in spec.Files", ref)
		}
		inputTars[dest] = canonicalFileTar(t, dest, content, int64(f.Mode))
	}
	return inputTars
}

// --------------------------------------------------------------------------.
// Golden test: AssembleImage (crossval vector).
// --------------------------------------------------------------------------.

func TestAssembleImage_Golden(t *testing.T) {
	vec := loadVector[assembleVector](t, "assemble", "empty_base_single_file.json")

	if vec.Inputs.Base != "oci:empty" {
		t.Fatalf("unsupported base type: %q", vec.Inputs.Base)
	}

	// Unmarshal spec from the vector.
	var spec lane.PackSpec
	if err := json.Unmarshal(vec.Inputs.Spec, &spec); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}

	inputTars := vectorInputTars(t, spec.Files, vec.Inputs.Files)

	result, err := executor.AssembleImage(empty.Image, &spec, inputTars)
	if err != nil {
		t.Fatalf("AssembleImage: %v", err)
	}

	layers, err := result.Image.Layers()
	if err != nil {
		t.Fatalf("layers: %v", err)
	}

	cfg, err := result.Image.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfgDigest, err := result.Image.ConfigName()
	if err != nil {
		t.Fatalf("config digest: %v", err)
	}

	// Verify config was applied.
	if cfg.Config.User != "65534:65534" {
		t.Errorf("user = %q, want 65534:65534", cfg.Config.User)
	}

	got := struct {
		ManifestDigest string `json:"manifest_digest"`
		ConfigDigest   string `json:"config_digest"`
		LayerCount     int    `json:"layer_count"`
	}{
		ManifestDigest: result.Digest.String(),
		ConfigDigest:   cfgDigest.String(),
		LayerCount:     len(layers),
	}

	if *update {
		updateVectorExpected(t, "assemble", "empty_base_single_file.json", got)
		return
	}

	if got.ManifestDigest != vec.Expected.ManifestDigest {
		t.Errorf("manifest_digest mismatch:\n  got:  %s\n  want: %s", got.ManifestDigest, vec.Expected.ManifestDigest)
	}
	if got.ConfigDigest != vec.Expected.ConfigDigest {
		t.Errorf("config_digest mismatch:\n  got:  %s\n  want: %s", got.ConfigDigest, vec.Expected.ConfigDigest)
	}
	if got.LayerCount != vec.Expected.LayerCount {
		t.Errorf("layer_count mismatch: got %d, want %d", got.LayerCount, vec.Expected.LayerCount)
	}
}

// --------------------------------------------------------------------------.
// Golden test: SpecHash (crossval vectors).
// --------------------------------------------------------------------------.

func TestSpecHash_Golden(t *testing.T) {
	files, err := fs.Glob(crossval.FS, "spechash/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no spechash vectors found")
	}

	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			vec := loadVector[specHashVector](t, "spechash", name)

			step := &lane.Step{
				Args: vec.Inputs.Step.Args,
				Env:  vec.Inputs.Step.Env,
			}

			imageDigest := primitive.Digest(vec.Inputs.ImageDigest)
			got := registry.SpecHash(step,
				imageDigest,
				toDigestMap(vec.Inputs.InputHashes),
				toDigestMap(vec.Inputs.SourceHashes),
			)

			if *update {
				updateVectorExpected(t, "spechash", name, struct {
					Hash string `json:"hash"`
				}{Hash: got.String()})
				return
			}

			if got.String() != vec.Expected.Hash {
				t.Errorf("hash mismatch:\n  got:  %s\n  want: %s", got, vec.Expected.Hash)
			}
		})
	}
}

// --------------------------------------------------------------------------.
// Non-golden tests (kept as-is, no vector files needed).
// --------------------------------------------------------------------------.

// TestAssembleImage_Deterministic verifies that two identical assemblies
// produce the same manifest digest -- the fundamental reproducibility
// property that cross-validation depends on.
func TestAssembleImage_Deterministic(t *testing.T) {
	spec := &lane.PackSpec{
		Files: []lane.PackFile{
			{From: lane.OutputRef{Step: "step", Output: "out"}, Dest: "/app", Mode: 0o755},
		},
	}
	inputs := map[string][]byte{"/app": canonicalFileTar(t, "/app", []byte("binary-content"), 0o755)}

	r1, err := executor.AssembleImage(empty.Image, spec, inputs)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := executor.AssembleImage(empty.Image, spec, inputs)
	if err != nil {
		t.Fatal(err)
	}

	if r1.Digest != r2.Digest {
		t.Errorf("non-deterministic assembly:\n  run 1: %s\n  run 2: %s", r1.Digest, r2.Digest)
	}
}

// TestAssembleImage_WithMutatedBase verifies assembly produces a DIFFERENT
// digest with a different base -- catching accidental base-image independence.
func TestAssembleImage_WithMutatedBase(t *testing.T) {
	spec := &lane.PackSpec{
		Files: []lane.PackFile{
			{From: lane.OutputRef{Step: "step", Output: "out"}, Dest: "/app", Mode: 0o755},
		},
	}
	inputs := map[string][]byte{"/app": canonicalFileTar(t, "/app", []byte("binary"), 0o755)}

	r1, err := executor.AssembleImage(empty.Image, spec, inputs)
	if err != nil {
		t.Fatal(err)
	}

	altBase, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Config: v1.Config{Labels: map[string]string{"base": "alt"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := executor.AssembleImage(altBase, spec, inputs)
	if err != nil {
		t.Fatal(err)
	}

	if r1.Digest == r2.Digest {
		t.Error("different bases should produce different digests")
	}
}
