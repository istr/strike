package deploy

import (
	"sort"
	"strings"
	"testing"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"github.com/istr/strike/specs"
)

// TestTrustLayerConformance asserts that specs/trust-layers.cue (the single
// source for the V / E / informational classification) agrees with where
// attestation.cue (internal collect-model) and predicate.cue (published
// statements) actually place each field. This is the machine-checkable form of
// the soundness note's "no E-link recorded as a V-link": the schemas are
// projections of the map and must not drift from it.
//
// Stage-1 scope: the engineDependent and informational sections of #Attestation
// and the engine-context and informational published predicates. The sealed
// section and the SLSA-provenance externalParameters projection are pinned in
// the map but not yet machine-checked (Stage-2).
func TestTrustLayerConformance(t *testing.T) {
	ctx := cuecontext.New()

	layers := mustCompile(t, ctx, "trust-layers.cue", stripForConcat(specs.TrustLayersSchema))
	// deploySchema is the existing concatenation of attestation.cue + predicate.cue
	// + the types they reference; reusing it keeps the schema set single-sourced.
	schema := mustCompile(t, ctx, "deploy schema", deploySchema)

	// Expected field-name sets, derived from the single-source map. The map key
	// is the logical field id, which equals the field label in both the
	// #Attestation sections and the published predicates for the Stage-1 fields.
	wantInternal := map[string]map[string]bool{"engineDependent": {}, "informational": {}}
	wantPublished := map[string]map[string]bool{"engine-context": {}, "informational": {}}

	fieldIter, err := layers.LookupPath(cue.ParsePath("fields")).Fields()
	if err != nil {
		t.Fatalf("iterate trust-layer map: %v", err)
	}
	for fieldIter.Next() {
		key := fieldIter.Selector().Unquoted()
		entry := fieldIter.Value()

		internal, err := entry.LookupPath(cue.ParsePath("internal")).String()
		if err != nil {
			t.Fatalf("field %q: read internal: %v", key, err)
		}
		published, err := entry.LookupPath(cue.ParsePath("published")).String()
		if err != nil {
			t.Fatalf("field %q: read published: %v", key, err)
		}

		section := internal
		if i := strings.IndexByte(internal, '.'); i >= 0 {
			section = internal[:i]
		}
		if set, ok := wantInternal[section]; ok {
			set[key] = true
		}
		if set, ok := wantPublished[published]; ok {
			set[key] = true
		}
	}

	cases := []struct {
		want map[string]bool
		def  string
	}{
		{wantInternal["engineDependent"], "#EngineDependent"},
		{wantInternal["informational"], "#Informational"},
		{wantPublished["engine-context"], "#EngineContextPredicate"},
		{wantPublished["informational"], "#InformationalPredicate"},
	}
	for _, c := range cases {
		assertFieldSet(t, schema, c.def, c.want)
	}
}

func mustCompile(t *testing.T, ctx *cue.Context, name, src string) cue.Value {
	t.Helper()
	v := ctx.CompileString(src)
	if err := v.Err(); err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return v
}

// assertFieldSet checks that the CUE definition at def has exactly the field
// names in want. Optional fields are included: the predicate and section fields
// are declared optional, and a plain LookupPath does not resolve them.
func assertFieldSet(t *testing.T, root cue.Value, def string, want map[string]bool) {
	t.Helper()
	got := map[string]bool{}
	iter, err := root.LookupPath(cue.ParsePath(def)).Fields(cue.Optional(true))
	if err != nil {
		t.Fatalf("%s: iterate fields: %v", def, err)
	}
	for iter.Next() {
		got[iter.Selector().Unquoted()] = true
	}
	if !equalStringSets(got, want) {
		t.Errorf("%s field set disagrees with trust-layers.cue:\n  got:  %v\n  want: %v",
			def, sortedKeys(got), sortedKeys(want))
	}
}

func equalStringSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
