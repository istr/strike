package main

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"testing"
)

// checkSource type-checks src under a strike-prefixed import path so that
// strikeNamed recognizes types declared in it. The fixtures import nothing, so
// the importer is never consulted.
func checkSource(t *testing.T, src string) *types.Package {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("github.com/istr/strike/flowcase", fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatalf("typecheck: %v", err)
	}
	return pkg
}

func namedType(t *testing.T, pkg *types.Package, name string) types.Type {
	t.Helper()
	obj := pkg.Scope().Lookup(name)
	if obj == nil {
		t.Fatalf("type %q not found", name)
	}
	return obj.Type()
}

const predicateSrc = "package flowcase\n" +
	"type Digest string\n" +
	"type Meta struct{ X int }\n"

func TestStrikeNamed(t *testing.T) {
	pkg := checkSource(t, predicateSrc)
	if strikeNamed(namedType(t, pkg, "Digest")) == nil {
		t.Errorf("Digest should be a strike named type")
	}
	if strikeNamed(namedType(t, pkg, "Meta")) == nil {
		t.Errorf("Meta should be a strike named type")
	}
	if strikeNamed(types.Typ[types.String]) != nil {
		t.Errorf("plain string is not a strike named type")
	}
}

func TestIsPlainString(t *testing.T) {
	pkg := checkSource(t, predicateSrc)
	if !isPlainString(types.Typ[types.String]) {
		t.Errorf("plain string should be plain string")
	}
	if isPlainString(namedType(t, pkg, "Digest")) {
		t.Errorf("Digest is a strike named type, not plain string")
	}
}

func TestIsScalarStrike(t *testing.T) {
	pkg := checkSource(t, predicateSrc)
	if !isScalarStrike(namedType(t, pkg, "Digest")) {
		t.Errorf("Digest has a basic underlying, should be scalar strike")
	}
	if isScalarStrike(namedType(t, pkg, "Meta")) {
		t.Errorf("Meta has a struct underlying, not scalar strike")
	}
	if isScalarStrike(types.Typ[types.String]) {
		t.Errorf("plain string is not a strike type")
	}
}

func TestIsAddressLike(t *testing.T) {
	pkg := checkSource(t, predicateSrc)
	if !isAddressLike(namedType(t, pkg, "Meta")) {
		t.Errorf("Meta is a strike named struct, should be address-like")
	}
	if isAddressLike(namedType(t, pkg, "Digest")) {
		t.Errorf("Digest is scalar, not address-like")
	}
}

func TestGateFindings(t *testing.T) {
	facts := []Fact{
		{Kind: "roundtrip-local", Pos: "a.go:1", Pkg: "p", Func: "F"},
		{Kind: "result-string-scalar", Pos: "a.go:2", Pkg: "p", Func: "G"},
		{Kind: "conversion", Pos: "a.go:3", Pkg: "p", Func: "H"},
		{Kind: "roundtrip-local", Pos: "a.gen.go:4", Pkg: "p", Func: "K", IsGen: true},
	}
	got := gateFindings(facts, nil)
	if len(got) != 2 {
		t.Fatalf("gateFindings returned %d, want 2 (non-gating and generated dropped): %+v", len(got), got)
	}
	kinds := map[string]bool{}
	for _, f := range got {
		kinds[f.Kind] = true
	}
	if !kinds["roundtrip-local"] || !kinds["result-string-scalar"] {
		t.Errorf("expected both gating kinds, got %v", kinds)
	}
}

func TestGateFindingsAllowlist(t *testing.T) {
	facts := []Fact{
		{Kind: "roundtrip-local", Pos: "a.go:1", Pkg: "p", Func: "F"},
		{Kind: "roundtrip-local", Pos: "a.go:2", Pkg: "p", Func: "Other"},
	}
	allow := []allowEntry{{pkg: "p", fn: "F", kind: "roundtrip-local", owner: "item-test", reason: "fixture"}}
	got := gateFindings(facts, allow)
	if len(got) != 1 || got[0].Func != "Other" {
		t.Fatalf("allowlist should suppress p.F only, got %+v", got)
	}
}

func TestCollectFlowFacts(t *testing.T) {
	dir, err := filepath.Abs("testdata/flowcase")
	if err != nil {
		t.Fatal(err)
	}
	facts, err := collect(dir, []string{"./..."})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	kinds := map[string]int{}
	for _, f := range facts {
		kinds[f.Kind]++
	}
	for _, want := range []string{"roundtrip-local", "result-string-scalar"} {
		if kinds[want] == 0 {
			t.Errorf("expected at least one %s fact, got kinds %v", want, kinds)
		}
	}
	if got := gateFindings(facts, allow); len(got) < 2 {
		t.Errorf("gate should flag both covered classes on the fixture, got %d: %+v", len(got), got)
	}
}
