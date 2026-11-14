package main

import (
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"

	"github.com/istr/strike/internal/testutil"
)

// TestAllFixturesBuild holds every testdata lane to validateLane, the gate
// every subcommand applies. An invalid_ fixture must be rejected with the
// error its rejects entry names: a negative that fails for an unrelated
// reason would otherwise pass unnoticed. A rejects entry whose fixture is
// gone fails too, so the table cannot outlive the files it describes.
func TestAllFixturesBuild(t *testing.T) {
	fixtures, err := filepath.Glob("testdata/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no fixtures found")
	}
	rejects := map[string]string{
		"invalid_capture_no_command.yaml": "captures.0.command",
	}
	for name := range rejects {
		if !slices.Contains(fixtures, filepath.Join("testdata", name)) {
			t.Errorf("rejects entry %s names no fixture in testdata", name)
		}
	}
	for _, path := range fixtures {
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			want, invalid := rejects[name]
			if invalid != strings.HasPrefix(name, "invalid_") {
				t.Fatal("an invalid_ fixture needs a rejects entry, and only an invalid_ fixture has one")
			}
			_, _, _, _, _, err := validateLane(path)
			switch {
			case !invalid && err != nil:
				t.Fatalf("validate: %v", err)
			case invalid && err == nil:
				t.Fatalf("validate accepted the fixture; want an error containing %q", want)
			case invalid && !strings.Contains(err.Error(), want):
				t.Fatalf("validate: %v; want an error containing %q", err, want)
			}
		})
	}
}

// TestBootstrapLaneValidates renders the bootstrap lane from its template the
// way the stage_0 build does -- a fetched commit and a harness root as the two
// embedded inputs -- and holds the result to the validation strike validate
// applies: parse, lane validation, DAG build and leaf topology. The inputs
// reach the loader through its overlay, so nothing is written into the tree;
// the root is the fixture anchor, because only its shape matters here.
func TestBootstrapLaneValidates(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(testutil.AnchorCertB64)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "bootstrap", "input")
	overlay := map[string]load.Source{
		filepath.Join(input, "HEAD"):           load.FromString(strings.Repeat("0", 40) + "\n"),
		filepath.Join(input, "caddy-root.crt"): load.FromBytes(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
	insts := load.Instances([]string{"./bootstrap"}, &load.Config{Dir: root, Overlay: overlay})
	if len(insts) != 1 {
		t.Fatalf("load bootstrap template: %d instances, want 1", len(insts))
	}
	if insts[0].Err != nil {
		t.Fatalf("load bootstrap template: %v", insts[0].Err)
	}
	out := cuecontext.New().BuildInstance(insts[0]).LookupPath(cue.ParsePath("out"))
	if vErr := out.Validate(cue.Concrete(true)); vErr != nil {
		t.Fatalf("render bootstrap lane: %v", vErr)
	}
	data, err := out.MarshalJSON()
	if err != nil {
		t.Fatalf("render bootstrap lane: %v", err)
	}
	path := filepath.Join(t.TempDir(), "lane.yaml")
	if wErr := os.WriteFile(path, data, 0o600); wErr != nil {
		t.Fatal(wErr)
	}
	if _, _, _, _, _, vErr := validateLane(path); vErr != nil {
		t.Fatalf("validate rendered bootstrap lane: %v", vErr)
	}
}
