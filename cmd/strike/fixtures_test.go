package main

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
					return
				}
				t.Fatalf("NewFilePath: %v", fpErr)
			}
			p, _, err := lane.Parse(fp)
			if err != nil {
				if strings.HasPrefix(filepath.Base(path), "invalid_") {
					return
				}
				t.Fatalf("parse: %v", err)
			}
			dag, err := lane.Build(p)
			if strings.HasPrefix(filepath.Base(path), "invalid_") {
				if err == nil {
					t.Fatal("expected build error for invalid fixture")
				}
				return
			}
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if depErr := dag.ValidateLeavesAreDeploys(p); depErr != nil {
				t.Fatalf("leaf-is-deploy policy (ADR-039 D5): %v", depErr)
			}
		})
	}
}
