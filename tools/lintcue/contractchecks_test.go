package main

import (
	"sort"
	"strings"
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

func TestPrimitiveConstraintsSkipBareIdentifiers(t *testing.T) {
	// A primitive whose value is a bare identifier owns no grammar, so it does
	// not claim the fields of that type; a primitive with a grammar still does.
	f, err := parser.ParseFile("p.cue", "#UserSpec: string\n#Alias: #Ident\n#Ident: =~\"^[a-z0-9]$\"\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	prims := primitiveConstraints([]*ast.File{f})
	grammar := renderConstraint(firstField(t, "#Ident: =~\"^[a-z0-9]$\"").Value)
	if len(prims) != 1 || prims[grammar] != "#Ident" {
		t.Fatalf("primitiveConstraints = %v, want only the #Ident grammar", prims)
	}
	if fs := appendFieldFindings(nil, firstField(t, "user: string"), prims); len(fs) != 0 {
		t.Errorf("string field: got %d findings, want 0: %v", len(fs), fs)
	}
}

func TestTierFindings(t *testing.T) {
	cases := []struct {
		name, dir, src, kind string
	}{
		{"downward", "lane", `import "` + contractPrefix + `primitive"`, ""},
		{"vector onto wire", "crossval", `import "` + contractPrefix + `lane"`, ""},
		{"lateral", "endpoint", `import "` + contractPrefix + `record"`, "tier-direction"},
		{"upward", "primitive", `import "` + contractPrefix + `lane"`, "tier-direction"},
		{"undeclared import", "lane", `import "strings"`, "undeclared-tier"},
		{"struct", "lane", `import "struct"`, ""},
		{"undeclared package", "probe", `x: 1`, "undeclared-tier"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := parser.ParseFile("t.cue", "package "+c.dir+"\n\n"+c.src+"\n")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			fs := appendTierFindings(nil, c.dir, []*ast.File{f})
			if c.kind == "" {
				if len(fs) != 0 {
					t.Fatalf("got %d findings, want 0: %v", len(fs), fs)
				}
				return
			}
			if len(fs) != 1 || !strings.Contains(fs[0], ": "+c.kind+": ") {
				t.Fatalf("got %v, want one %s finding", fs, c.kind)
			}
		})
	}
}

func TestHasDefaultArm(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		{`x: *"a" | string`, true},
		{`x: string | *"a"`, true},
		{`x: (*1 | int) & >0`, true},
		{`x: "a" | string`, false},
		{`x: 2 * 3`, false},
		{`x: string`, false},
	}
	for _, c := range cases {
		if got := hasDefaultArm(firstField(t, c.src).Value); got != c.want {
			t.Errorf("hasDefaultArm(%q) = %v, want %v", c.src, got, c.want)
		}
	}
}

func TestDefaultFindings(t *testing.T) {
	// A default arm stands at a regular field; at an optional field or in a
	// definition of its own it is a finding.
	cases := []struct {
		src, kind string
	}{
		{`port?: *1 | int`, "optional-default"},
		{`#Port: *443 | int`, "definition-default"},
		{`port: *1 | int`, ""},
		{`port?: int`, ""},
	}
	for _, c := range cases {
		fs := appendFieldFindings(nil, firstField(t, c.src), nil)
		if c.kind == "" {
			if len(fs) != 0 {
				t.Errorf("%q: got %v, want no finding", c.src, fs)
			}
			continue
		}
		if len(fs) != 1 || !strings.Contains(fs[0], ": "+c.kind+": ") {
			t.Errorf("%q: got %v, want one %s finding", c.src, fs, c.kind)
		}
	}
}

func TestRecursionFindings(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"reference", "#L: {head: string, next?: #L}", []string{
			"definition #L reaches itself: #L -> #L",
		}},
		{"composition", "#T: {children?: [...#T & {x?: int}]}", []string{
			"definition #T reaches itself: #T -> #T",
		}},
		{"embedding", "#E: {next?: {#E, y?: int}}", []string{
			"definition #E reaches itself: #E -> #E",
		}},
		{"indirect", "#A: {b?: #B}\n#B: {a?: #A}", []string{
			"definition #A reaches itself: #A -> #B -> #A",
			"definition #B reaches itself: #B -> #A -> #B",
		}},
		{"field of a definition", "#A: {b?: #B.c}\n#B: {c?: #A}", []string{
			"definition #A reaches itself: #A -> #B -> #A",
			"definition #B reaches itself: #B -> #A -> #B",
		}},
		{"acyclic", "#A: {b?: #B, c?: #B}\n#B: {d?: string}", nil},
		{"qualified", "#A: {b?: other.#A}", nil},
		{"label", "#A: {\"#A\"?: string}", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := parser.ParseFile("t.cue", c.src)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			var got []string
			for _, fnd := range recursionFindings([]*ast.File{f}) {
				_, msg, ok := strings.Cut(fnd, ": recursive-definition: ")
				if !ok {
					t.Fatalf("not a recursive-definition finding: %q", fnd)
				}
				got = append(got, msg)
			}
			sort.Strings(got)
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Fatalf("recursionFindings = %q, want %q", got, c.want)
			}
		})
	}
}
