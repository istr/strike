package main

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

func checkSource(t *testing.T, src string) *types.Package {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("p", fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatalf("typecheck: %v", err)
	}
	return pkg
}

func named(t *testing.T, pkg *types.Package, name string) *types.Named {
	t.Helper()
	obj := pkg.Scope().Lookup(name)
	if obj == nil {
		t.Fatalf("type %q not found", name)
	}
	n, ok := obj.Type().(*types.Named)
	if !ok {
		t.Fatalf("type %q is not a named type", name)
	}
	return n
}

func TestBehavioralNamed(t *testing.T) {
	src := "package p\n" +
		"import (\"os\"; \"sync\")\n" +
		"type Iface interface{ M() }\n" +
		"type Fn func(int) int\n" +
		"type Ch chan int\n" +
		"type Svc struct{ H Iface }\n" +
		"type Locked struct{ mu sync.Mutex }\n" +
		"type Handle struct{ f *os.File }\n" +
		"type Data struct{ A, B string }\n"
	pkg := checkSource(t, src)
	cases := map[string]bool{
		"Iface": true, "Fn": true, "Ch": true, "Svc": true,
		"Locked": true, "Handle": true, "Data": false,
	}
	for name, want := range cases {
		if got := behavioralNamed(named(t, pkg, name)); got != want {
			t.Errorf("behavioralNamed(%s) = %v, want %v", name, got, want)
		}
	}
}

func TestHasJSONField(t *testing.T) {
	src := "package p\n" +
		"type Tagged struct{ X int `json:\"x\"` }\n" +
		"type Plain struct{ X int }\n"
	pkg := checkSource(t, src)
	for name, want := range map[string]bool{"Tagged": true, "Plain": false} {
		st := named(t, pkg, name).Underlying().(*types.Struct)
		if got := hasJSONField(st); got != want {
			t.Errorf("hasJSONField(%s) = %v, want %v", name, got, want)
		}
	}
}

func TestCueGoTypeNames(t *testing.T) {
	names, err := cueGoTypeNames("testdata")
	if err != nil {
		t.Fatalf("cueGoTypeNames: %v", err)
	}
	for _, want := range []string{"Bar", "Widget"} {
		if !names[want] {
			t.Errorf("expected %q among cue names %v", want, names)
		}
	}
}
