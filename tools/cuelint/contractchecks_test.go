package main

import (
	"testing"

	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/parser"
)

func fields(t *testing.T, src string) []*ast.Field {
	t.Helper()
	f, err := parser.ParseFile("t.cue", src)
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	var out []*ast.Field
	for _, d := range f.Decls {
		if fld, ok := d.(*ast.Field); ok {
			out = append(out, fld)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no field parsed from %q", src)
	}
	return out
}

func firstField(t *testing.T, src string) *ast.Field {
	t.Helper()
	return fields(t, src)[0]
}

func TestIsStringDisjunction(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		{`x: "a" | "b"`, true},
		{`x: "a" | "b" | "c"`, true},
		{`x: "a"`, false},
		{`x: "a" | string`, false},
		{`x: "a" | 3`, false},
		{`x: string`, false},
	}
	for _, c := range cases {
		got := isStringDisjunction(firstField(t, c.src).Value)
		if got != c.want {
			t.Errorf("isStringDisjunction(%q) = %v, want %v", c.src, got, c.want)
		}
	}
}

func TestLabelAndDefinition(t *testing.T) {
	if n := labelName(firstField(t, `format: "x"`).Label); n != "format" {
		t.Errorf("labelName plain = %q, want format", n)
	}
	if n := labelName(firstField(t, `#Def: "x"`).Label); n != "#Def" {
		t.Errorf("labelName def = %q, want #Def", n)
	}
	if !isDefinitionLabel("#Def") || isDefinitionLabel("format") {
		t.Errorf("isDefinitionLabel misclassified")
	}
}

func TestLossyMapKey(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"lossy", `s: {[ID=primitive.#Identifier]: T} @go(S,type=map[string]T)`, true},
		{"preserved", `p: {[ID=primitive.#Identifier]: T} @go(P,type=map[primitive.Identifier]T)`, false},
		{"plain", `e: {[string]: string} @go(E)`, false},
		{"noattr", `n: {[ID=primitive.#Identifier]: T}`, false},
	}
	for _, c := range cases {
		_, got := lossyMapKey(firstField(t, c.src))
		if got != c.want {
			t.Errorf("%s: lossyMapKey = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPrimitiveReuse(t *testing.T) {
	// A primitive owns a regex grammar; a field re-inlining the identical
	// grammar is flagged, a field referencing the primitive is not.
	prim := firstField(t, "#Ident: =~\"^[a-z0-9]$\"")
	prims := map[string]string{renderConstraint(prim.Value): "#Ident"}

	reinlined := firstField(t, "host: =~\"^[a-z0-9]$\"")
	if fs := appendFieldFindings(nil, reinlined, prims); len(fs) != 1 {
		t.Errorf("re-inlined grammar: got %d findings, want 1: %v", len(fs), fs)
	}
	referenced := firstField(t, "host: primitive.#Ident")
	if fs := appendFieldFindings(nil, referenced, prims); len(fs) != 0 {
		t.Errorf("reference: got %d findings, want 0: %v", len(fs), fs)
	}
}

func TestInlineDisjunctionFinding(t *testing.T) {
	// A plain field with an inline string disjunction is flagged; a named
	// definition with the same value is not (rule 5 targets fields).
	fld := firstField(t, `type: "git" | "tarball"`)
	if fs := appendFieldFindings(nil, fld, nil); len(fs) != 1 {
		t.Fatalf("field disjunction: got %d findings, want 1: %v", len(fs), fs)
	}
	def := firstField(t, `#Kind: "git" | "tarball"`)
	if fs := appendFieldFindings(nil, def, nil); len(fs) != 0 {
		t.Errorf("named disjunction: got %d findings, want 0: %v", len(fs), fs)
	}
}
