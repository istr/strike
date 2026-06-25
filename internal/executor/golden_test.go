package executor_test

import (
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/test/crossval"
)

var update = flag.Bool("update", false, "update cross-validation vector expected fields")

// toDigestMap converts a map[string]string (from JSON vectors) to map[string]lane.DigestRef.
func toDigestMap(m map[string]string) map[string]lane.DigestRef {
	out := make(map[string]lane.DigestRef, len(m))
	for k, v := range m {
		out[k] = lane.MustParseDigest(v)
	}
	return out
}

// writeVectorFiles writes vector file entries to a temp dir and returns
// inputPaths keyed by Dest (matching the contract of addFileLayers).
func writeVectorFiles(t *testing.T, specFiles []lane.PackFile, vecFiles map[string]assembleFileEntry) map[string]string {
	t.Helper()
	fromToDest := make(map[string]string, len(specFiles))
	for _, pf := range specFiles {
		fromToDest[string(pf.From.Step)+"."+string(pf.From.Output)] = pf.Dest.String()
	}
	tmp := t.TempDir()
	inputPaths := make(map[string]string, len(vecFiles))
	for ref, f := range vecFiles {
		content := decodeBase64(t, f.ContentBase64)
		hostPath := filepath.Join(tmp, filepath.Base(ref))
		if err := os.WriteFile(hostPath, content, 0o600); err != nil {
			t.Fatalf("write test file %s: %v", ref, err)
		}
		if f.Mode < 0 || f.Mode > 0o7777 {
			t.Fatalf("test file %s: invalid mode %d", ref, f.Mode)
		}
		if err := os.Chmod(hostPath, os.FileMode(f.Mode&0o7777)); err != nil {
			t.Fatalf("chmod test file %s: %v", ref, err)
		}
		dest, ok := fromToDest[ref]
		if !ok {
			t.Fatalf("vector file %q not found in spec.Files", ref)
		}
		inputPaths[dest] = hostPath
	}
	return inputPaths
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

	inputPaths := writeVectorFiles(t, spec.Files, vec.Inputs.Files)

	result, err := executor.AssembleImage(empty.Image, &spec, inputPaths)
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

			got := registry.SpecHash(step,
				lane.MustParseDigest(vec.Inputs.ImageDigest),
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
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "app")
	testutil.WriteTestBinary(t, binPath, []byte("binary-content"))

	spec := &lane.PackSpec{
		Files: []lane.PackFile{
			{From: lane.OutputRef{Step: "step", Output: "out"}, Dest: "/app", Mode: 0o755},
		},
	}
	inputs := map[string]string{"/app": binPath}

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
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "app")
	testutil.WriteTestBinary(t, binPath, []byte("binary"))

	spec := &lane.PackSpec{
		Files: []lane.PackFile{
			{From: lane.OutputRef{Step: "step", Output: "out"}, Dest: "/app", Mode: 0o755},
		},
	}
	inputs := map[string]string{"/app": binPath}

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
