package main

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), Analyzer,
		"github.com/istr/strike/conv",
		"github.com/istr/strike/use",
		"github.com/istr/strike/internal/mediator",
	)
}
