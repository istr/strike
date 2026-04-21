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
			p, err := lane.Parse(path)
			if err != nil {
				if strings.HasPrefix(filepath.Base(path), "invalid_") {
					return // negative fixture, parse error expected
				}
				t.Fatalf("parse: %v", err)
			}
			_, err = lane.Build(p)
			if strings.HasPrefix(filepath.Base(path), "invalid_") {
				if err == nil {
					t.Fatal("expected build error for invalid fixture")
				}
				return
			}
			if err != nil {
				t.Fatalf("build: %v", err)
			}
		})
	}
}
