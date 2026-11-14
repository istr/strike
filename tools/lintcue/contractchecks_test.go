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

func TestCollectionDefect(t *testing.T) {
	cases := []struct {
		src    string
		defect bool
	}{
		{`args: [...string]`, true},
		{`args!: [...string]`, true},
		{`args?: [...string]`, false},
		{`args: [string, ...string]`, false},
		{`args: []`, false},
		{`args: [string]`, false},
		{`env: [string]: string`, true},
		{`env: {[string]: string}`, true},
		{`env?: {[string]: string}`, false},
		{`env: {[string]: string, x: int}`, false},
		{`env: {}`, false},
		{`#Def: [...string]`, false},
		{`[string]: [...string]`, false},
	}
	for _, c := range cases {
		if got := collectionDefect(firstField(t, c.src)) != ""; got != c.defect {
			t.Errorf("collectionDefect(%q) reports %v, want %v", c.src, got, c.defect)
		}
	}
}

func TestCollectionFindings(t *testing.T) {
	// The deferred site is matched by its path from the definition, a nested
	// site is found and named by its path, a field inside a pattern
	// constraint's value is a site whose path spells the pattern, a quoted
	// label is spelled as written, a pattern constraint's value itself and a
	// field outside any definition are not sites, and a deferral that matches
	// no site is reported.
	src := "#Peer: {\n\tresolved: [...string]\n\tspec: {files: [...string]}\n\tm?: {[string]: [...string]}\n\tn?: {[string]: {x: [...string]}}\n\t\"q-x\": [...string]\n}\nfields: [string]: string\n"
	f, err := parser.ParseFile("t.cue", src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	deferrals := []collectionDeferral{
		{dir: "attest", path: "#Peer.resolved", owner: "item-x"},
		{dir: "attest", path: "#Peer.gone", owner: "item-x"},
	}
	fs := collectionFindings(map[string][]*ast.File{"attest": {f}}, deferrals)
	sort.Strings(fs)
	if len(fs) != 4 ||
		!strings.Contains(fs[0], ": stale-deferral: #Peer.gone is deferred to item-x") ||
		!strings.Contains(fs[1], ": required-collection: #Peer.spec.files is a required open list") ||
		!strings.Contains(fs[2], ": required-collection: #Peer.n.[string].x is a required open list") ||
		!strings.Contains(fs[3], ": required-collection: #Peer.\"q-x\" is a required open list") {
		t.Fatalf("collectionFindings = %v, want the stale #Peer.gone and the sites #Peer.spec.files, #Peer.n.[string].x and #Peer.\"q-x\"", fs)
	}
}
