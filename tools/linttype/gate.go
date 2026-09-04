package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// factsAnalyzer runs the type-flow extractor once per package and hands the
// facts to the gates below. It reports nothing itself: every gate selects the
// kinds it owns from this one traversal, which is why the conversion
// ownership check is not a second detector.
var factsAnalyzer = &analysis.Analyzer{
	Name:       "linttypefacts",
	Doc:        "extract type-flow facts for the gates in this tool",
	Run:        runFacts,
	ResultType: reflect.TypeOf([]Fact(nil)),
}

// ConvOwnerAnalyzer reports a conversion of a strike named type sitting
// directly in a call argument, outside the type's own defining package and
// the allowlist.
var ConvOwnerAnalyzer = &analysis.Analyzer{
	Name:     "linttypeconv",
	Doc:      "report conversions of strike named types used directly as call arguments",
	Requires: []*analysis.Analyzer{factsAnalyzer},
	Run:      gateRun(convKinds),
}

// FlowAnalyzer reports the three near-zero-false-positive flow classes:
// a value detyped and retyped within one function, a named scalar returned as
// a plain string, and a detyping that bypasses the type's String() boundary.
var FlowAnalyzer = &analysis.Analyzer{
	Name:     "linttypeflow",
	Doc:      "report type-flow leaks the type checker can see",
	Requires: []*analysis.Analyzer{factsAnalyzer},
	Run:      gateRun(flowKinds),
}

func runFacts(pass *analysis.Pass) (any, error) {
	path := pass.Pkg.Path()
	if skipPackage(path) {
		return []Fact(nil), nil
	}
	root, err := moduleRoot(pass)
	if err != nil {
		return nil, err
	}
	c := &collector{seen: map[string]bool{}, fset: pass.Fset, repoRoot: root}
	u := unit{PkgPath: path, TypesInfo: pass.TypesInfo}
	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename
		if !strings.HasPrefix(fname, root) {
			continue // cgo/generated outside tree
		}
		c.walkFile(u, file)
	}
	return c.facts, nil
}

// gateRun reports the findings of the given kinds. The common drops --
// non-gating kinds, generated files, sanctioned boundaries, allowlisted sites
// -- stay in gateFindings so the gate and the survey agree on what counts.
func gateRun(kinds map[string]bool) func(*analysis.Pass) (any, error) {
	return func(pass *analysis.Pass) (any, error) {
		facts, ok := pass.ResultOf[factsAnalyzer].([]Fact)
		if !ok {
			return nil, fmt.Errorf("facts result is %T, want []Fact",
				pass.ResultOf[factsAnalyzer])
		}
		for _, f := range gateFindings(facts, allow) {
			if !kinds[f.Kind] {
				continue
			}
			pass.Reportf(f.tokenPos, "%s", gateMessage(f))
		}
		return nil, nil
	}
}

// moduleRoot locates the directory holding the module's go.mod by walking up
// from the first file of the pass, so a finding's Pos renders relative to the
// tree root exactly as the survey renders it.
func moduleRoot(pass *analysis.Pass) (string, error) {
	if len(pass.Files) == 0 {
		return "", nil
	}
	dir := filepath.Dir(pass.Fset.Position(pass.Files[0].Pos()).Filename)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod above %s", dir)
		}
		dir = parent
	}
}
