package main

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), Analyzer,
		"github.com/istr/strike/conv",
		"github.com/istr/strike/use",
	)
}

// TestAllowlist exercises the allowlist branch with a synthetic entry, so the
// production allowlist can stay empty while the mechanism keeps a test.
func TestAllowlist(t *testing.T) {
	saved := allow
	t.Cleanup(func() { allow = saved })
	allow = []struct{ pkg, callee, reason string }{
		{
			pkg:    "github.com/istr/strike/allowed",
			callee: "sink",
			reason: "fixture exercising the allowlist branch",
		},
	}
	analysistest.Run(t, analysistest.TestData(), Analyzer,
		"github.com/istr/strike/allowed",
	)
}

func TestStutterAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), StutterAnalyzer,
		"github.com/istr/strike/stutter",
	)
}
