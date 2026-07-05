package lane_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
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
					return // negative fixture, file may not be regular
				}
				t.Fatalf("NewFilePath: %v", fpErr)
			}
			p, index, _, err := lane.Parse(fp)
			if err != nil {
				if strings.HasPrefix(filepath.Base(path), "invalid_") {
					return // negative fixture, parse error expected
				}
				t.Fatalf("parse: %v", err)
			}

			if err = lane.ValidateLane(p, index); err != nil {
				if strings.HasPrefix(filepath.Base(path), "invalid_") {
					return // negative fixture, validation error expected
				}
				t.Fatalf("validate: %v", err)
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
