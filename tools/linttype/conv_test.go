package main

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestConvOwnerAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), ConvOwnerAnalyzer,
		"github.com/istr/strike/conv",
		"github.com/istr/strike/use",
	)
}

// TestAllowlist exercises the allowlist branch with a synthetic entry, so the
// production allowlist keeps only the entries a roadmap item owns while the
// mechanism keeps a test.
func TestAllowlist(t *testing.T) {
	saved := allow
	t.Cleanup(func() { allow = saved })
	allow = []allowEntry{
		{
			pkg:    "github.com/istr/strike/allowed",
			fn:     "onAllowlist",
			kind:   "conv-owner",
			owner:  "test-fixture",
			reason: "fixture exercising the allowlist branch",
		},
	}
	analysistest.Run(t, analysistest.TestData(), ConvOwnerAnalyzer,
		"github.com/istr/strike/allowed",
	)
}

func TestStutterAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), StutterAnalyzer,
		"github.com/istr/strike/stutter",
	)
}
