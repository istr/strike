package main

import (
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/testutil"
)

func TestAllFixturesBuild(t *testing.T) {
	fixtures, err := filepath.Glob("testdata/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no fixtures found")
	}
	for _, path := range fixtures {
		t.Run(filepath.Base(path), func(t *testing.T) {
			fp, fpErr := lane.NewFilePath(path)
			if fpErr != nil {
				if strings.HasPrefix(filepath.Base(path), "invalid_") {
					return
				}
				t.Fatalf("NewFilePath: %v", fpErr)
			}
			p, index, _, err := lane.Parse(fp)
			if err != nil {
				if strings.HasPrefix(filepath.Base(path), "invalid_") {
					return
				}
				t.Fatalf("parse: %v", err)
			}
			dag, err := lane.Build(p, index)
			if strings.HasPrefix(filepath.Base(path), "invalid_") {
				if err == nil {
					t.Fatal("expected build error for invalid fixture")
				}
				return
			}
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if depErr := dag.ValidateDAG(p); depErr != nil {
				t.Fatalf("leaf topology violated: %v", depErr)
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
