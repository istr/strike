package main

import (
	"sort"
	"strings"
	"testing"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
)

// walkSource compiles src as one package and walks its definitions.
func walkSource(t *testing.T, src string) (*valueWalk, error) {
	t.Helper()
	ctx := cuecontext.New()
	v := ctx.CompileString(src)
	if err := v.Err(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	return walkDefinitions(v, compileEmpties(ctx))
}

// messages returns, sorted, the text that follows the kind in every finding of
// fs of that kind.
func messages(t *testing.T, fs []string, kind string) []string {
	t.Helper()
	var out []string
	for _, f := range fs {
		if _, msg, ok := strings.Cut(f, ": "+kind+": "); ok {
			out = append(out, msg)
		}
	}
	sort.Strings(out)
	return out
}

func TestWalkSites(t *testing.T) {
	// A composition is entered and a bare reference is not; every entry beyond
	// the declared fields and every list element is spelled [_]; a list element
	// is not checked, its fields are.
	src := `
#Leaf: {
	a?: string
	b?: [...string]
}
#Inner: {
	a: {
		x: string
	}
}
#Id: =~"^[a-z]+$"
#Probe: {
	ref:      #Leaf
	comp:     #Leaf & {a?: "x"}
	compDeep: #Inner & {a: {x: *"d" | string}}
	open: {
		k: string
		...
	}
	keyed?: {[#Id]: [...string]}
	list: [...{e?: string}]
	tuple: [{t?: string}, ...{t?: string}]
	nested: {deep: {d?: string}}
	"_q"?: string
}
`
	w, err := walkSource(t, src)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	got := messages(t, appendEmptyFindings(nil, "p", w, map[string]bool{}), "empty-value")
	want := []string{
		`#Inner.a.x accepts ""`,
		`#Leaf.a accepts ""`,
		`#Leaf.b accepts []`,
		`#Probe."_q" accepts ""`,
		`#Probe.comp accepts {}`,
		`#Probe.comp.b accepts []`,
		`#Probe.compDeep accepts {}`,
		`#Probe.compDeep.a accepts {}`,
		`#Probe.compDeep.a.x accepts ""`,
		`#Probe.keyed accepts {}`,
		`#Probe.keyed.[_] accepts []`,
		`#Probe.list accepts []`,
		`#Probe.list.[_].e accepts ""`,
		`#Probe.nested accepts {}`,
		`#Probe.nested.deep accepts {}`,
		`#Probe.nested.deep.d accepts ""`,
		`#Probe.open.[_] accepts "" null [] {}`,
		`#Probe.open.k accepts ""`,
		`#Probe.ref accepts {}`,
		`#Probe.tuple.[_].t accepts ""`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("empty-value sites:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestWalkUnions(t *testing.T) {
	// A union of named definitions is no finding; an inline arm is, also as a
	// list element, beside null, and inside a conjunction.
	src := `
#A: {a?: string}
#B: {b?: int}
#Open: {...}
#Named: #A | #B
#Inline: #A | {z: string}
#P: {
	u: {p: string} | {q: int}
	v: #A | #B
	l: [...({p: string} | {q: int})]
	n?: null | #A
	c: #Open & ({p?: string} | {q?: int})
}
`
	w, err := walkSource(t, src)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	got := messages(t, w.findings, "union-arm")
	want := []string{
		"#Inline is a union with an arm that is not a named definition",
		"#P.c is a union with an arm that is not a named definition",
		"#P.l.[_] is a union with an arm that is not a named definition",
		"#P.n is a union with an arm that is not a named definition",
		"#P.u is a union with an arm that is not a named definition",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("union-arm findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestWalkTakesScalarConjunct(t *testing.T) {
	// A value indexed by a field the schema leaves open has no kind; its
	// conjunct of string kind makes it a scalar, which the walk does not enter.
	src := `
#P: "a" | "b"
#L: "x" | "y"
table: [#P]: #L
table: {a: "x", b: "y"}
#E: {
	p: #P
	l: #L & table[p]
}
`
	if k := cuecontext.New().CompileString(src).LookupPath(cue.ParsePath("#E.l")).IncompleteKind(); k != cue.BottomKind {
		t.Fatalf("#E.l has kind %v, want none", k)
	}
	if _, err := walkSource(t, src); err != nil {
		t.Fatalf("walk: %v", err)
	}
}

func TestWalkEntersValueOfNoKind(t *testing.T) {
	// A struct of optional fields under struct.MinFields(1) has no kind as a
	// schema, rejects {} and lists its fields; the walk enters it and reaches
	// the site below it.
	src := `
import "struct"

#M: {
	m: {a?: string} & struct.MinFields(1)
}
`
	if k := cuecontext.New().CompileString(src).LookupPath(cue.ParsePath("#M.m")).IncompleteKind(); k != cue.BottomKind {
		t.Fatalf("#M.m has kind %v, want none", k)
	}
	w, err := walkSource(t, src)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if set, ok := w.accepts["#M.m"]; ok {
		t.Errorf("#M.m accepts %08b, want none", set)
	}
	if set := w.accepts["#M.m.a"]; set != 1 {
		t.Errorf(`#M.m.a accepts %08b, want "" alone`, set)
	}
}

func TestWalkStopsOnValueOfNoKind(t *testing.T) {
	// An open struct under struct.MinFields(1) has no kind as a schema and lists
	// nothing: its open remainder is neither a field nor a pattern. The walk
	// cannot classify it and stops with an error that names the site.
	src := `
import "struct"

#M: {
	m: {...} & struct.MinFields(1)
}
`
	m := cuecontext.New().CompileString(src).LookupPath(cue.ParsePath("#M.m"))
	if k := m.IncompleteKind(); k != cue.BottomKind {
		t.Fatalf("#M.m has kind %v, want none", k)
	}
	it, err := m.Fields(cue.Optional(true), cue.Patterns(true))
	if err != nil {
		t.Fatalf("fields of #M.m: %v", err)
	}
	if it.Next() {
		t.Fatalf("#M.m lists %v, want nothing", it.Selector())
	}
	_, err = walkSource(t, src)
	if err == nil || !strings.Contains(err.Error(), "#M.m has a value of no kind") {
		t.Fatalf("walk error = %v, want one naming #M.m", err)
	}
}

func TestValueFindings(t *testing.T) {
	insts, err := contractInstances("testdata")
	if err != nil {
		t.Fatalf("contractInstances: %v", err)
	}
	site := `foo #Bar.x accepts ""`
	cases := []struct {
		name       string
		deferrals  map[string][]string
		exemptions []string
		want       []string
	}{
		{"reported", nil, nil, []string{`empty-value: #Bar.x accepts ""`}},
		{"deferred", map[string][]string{"item-x": {site}}, nil, nil},
		{"exempt", nil, []string{site}, nil},
		{"stale", map[string][]string{"item-x": {"foo #Bar.x accepts {}"}}, []string{`foo #Gone accepts ""`}, []string{
			`empty-value: #Bar.x accepts ""`,
			`stale-deferral: #Bar.x accepts {} is deferred to item-x but matches no finding`,
			`stale-exemption: #Gone accepts "" is exempt but matches no finding`,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs, err := valueFindings(insts, c.deferrals, c.exemptions)
			if err != nil {
				t.Fatalf("valueFindings: %v", err)
			}
			var got []string
			for _, f := range fs {
				_, rest, _ := strings.Cut(f, ": ")
				got = append(got, rest)
			}
			sort.Strings(got)
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Fatalf("valueFindings = %q, want %q", got, c.want)
			}
			for _, f := range fs {
				if strings.Contains(f, ": empty-value: ") && !strings.Contains(f, "foo.cue:4: ") {
					t.Errorf("empty-value finding %q does not name foo.cue line 4", f)
				}
			}
		})
	}
}

func TestContractFindings(t *testing.T) {
	// With a definition that reaches itself the evaluation does not run: the
	// field that accepts the empty string is not reported.
	cases := []struct {
		root string
		want []string
	}{
		{"testdata", []string{
			`empty-value: #Bar.x accepts ""`,
			`undeclared-tier: package directory "foo" has no declared tier`,
		}},
		{"testdata/recursion", []string{
			"recursive-definition: definition #L reaches itself: #L -> #L",
			`undeclared-tier: package directory "rec" has no declared tier`,
		}},
	}
	for _, c := range cases {
		t.Run(c.root, func(t *testing.T) {
			fs, err := contractFindings(c.root, nil, nil)
			if err != nil {
				t.Fatalf("contractFindings: %v", err)
			}
			var got []string
			for _, f := range fs {
				_, rest, _ := strings.Cut(f, ": ")
				got = append(got, rest)
			}
			sort.Strings(got)
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Fatalf("contractFindings = %q, want %q", got, c.want)
			}
		})
	}
}

func TestEmptyAllowances(t *testing.T) {
	// Every deferral names its owner, every entry is spelled
	// "<dir> <site> accepts <values>", and no site is listed twice.
	seen := map[string]bool{}
	check := func(s string) {
		dir, rest, _ := strings.Cut(s, " ")
		if _, ok := contractTiers[dir]; !ok || !strings.Contains(rest, " accepts ") || seen[s] {
			t.Errorf("entry %q is malformed or listed twice", s)
		}
		seen[s] = true
	}
	for owner, sites := range emptyDeferrals {
		if owner == "" {
			t.Errorf("deferrals without an owner: %v", sites)
		}
		for _, s := range sites {
			check(s)
		}
	}
	for _, s := range emptyExemptions {
		check(s)
	}
}
