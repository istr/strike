package deploy

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"github.com/istr/strike/specs"
)

// TestTrustLayerConformance asserts that specs/meta-trust-layers.cue (the single
// source for the V / E / informational classification) agrees with where
// attest-attestation.cue (internal collect-model) and attest-predicate.cue (published
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

	layers := mustCompile(t, ctx, "meta-trust-layers.cue", stripForConcat(specs.TrustLayersSchema))
	// deploySchema is the existing concatenation of attest-attestation.cue + attest-predicate.cue
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

// TestLayerDecisionProcedure asserts that a field's trust layer is a pure
// consequence of its provenance, per the decision procedure in
// ATTESTATION-SOUNDNESS-AND-THE-TRUST-BOUNDARY.md. meta-trust-layers.cue encodes the
// rules once, as the data map layerOf; this test restates them independently and
// fails if the two disagree -- so the procedure is checked against a spec, not
// against itself. It also pins two structural invariants: a field's derived layer
// matches the section it lives in, and only a CP-observed fact may be
// declaration-hardened.
func TestLayerDecisionProcedure(t *testing.T) {
	ctx := cuecontext.New()
	layers := mustCompile(t, ctx, "meta-trust-layers.cue", stripForConcat(specs.TrustLayersSchema))

	// The rules, restated independently of the CUE: V is CP-sealed canonical bytes
	// or a CP-verified external observation; E is an engine chain assertion;
	// everything else carries no trust claim.
	wantLayerOf := map[string]string{
		"cpSealed":             "V",
		"cpObserved":           "V",
		"engineChainAssertion": "E",
		"engineSelfReport":     "informational",
		"containerProduced":    "informational",
		"hostAsserted":         "informational",
	}
	gotLayerOf := map[string]string{}
	mapIter, err := layers.LookupPath(cue.ParsePath("layerOf")).Fields()
	if err != nil {
		t.Fatalf("iterate layerOf: %v", err)
	}
	for mapIter.Next() {
		v, verr := mapIter.Value().String()
		if verr != nil {
			t.Fatalf("layerOf[%s]: %v", mapIter.Selector().Unquoted(), verr)
		}
		gotLayerOf[mapIter.Selector().Unquoted()] = v
	}
	if !reflect.DeepEqual(gotLayerOf, wantLayerOf) {
		t.Errorf("layerOf disagrees with the decision rules (totality / exclusivity / correctness):\n  got:  %v\n  want: %v", gotLayerOf, wantLayerOf)
	}

	// Section -> layer, for the structural cross-check below.
	sectionLayer := map[string]string{}
	secIter, err := layers.LookupPath(cue.ParsePath("sections")).Fields()
	if err != nil {
		t.Fatalf("iterate sections: %v", err)
	}
	for secIter.Next() {
		l, lerr := secIter.Value().LookupPath(cue.ParsePath("layer")).String()
		if lerr != nil {
			t.Fatalf("sections[%s].layer: %v", secIter.Selector().Unquoted(), lerr)
		}
		sectionLayer[secIter.Selector().Unquoted()] = l
	}

	fieldIter, err := layers.LookupPath(cue.ParsePath("fields")).Fields()
	if err != nil {
		t.Fatalf("iterate fields: %v", err)
	}
	for fieldIter.Next() {
		key := fieldIter.Selector().Unquoted()
		entry := fieldIter.Value()

		prov, err := entry.LookupPath(cue.ParsePath("provenance")).String()
		if err != nil {
			t.Fatalf("field %q: read provenance: %v", key, err)
		}
		layer, err := entry.LookupPath(cue.ParsePath("layer")).String()
		if err != nil {
			t.Fatalf("field %q: read derived layer: %v", key, err)
		}

		// The derived layer must equal layerOf[provenance] -- i.e. CUE actually
		// performed the derivation, not a stray literal that happens to type-check.
		if want := wantLayerOf[prov]; layer != want {
			t.Errorf("field %q: derived layer %q != layerOf[%q]=%q", key, layer, prov, want)
		}

		// The derived layer must match the section the field occupies in the
		// collect-model (sealed=V, engineDependent=E, informational=informational).
		// Skip fields absent from the collect-model (internal "-").
		internal, err := entry.LookupPath(cue.ParsePath("internal")).String()
		if err != nil {
			t.Fatalf("field %q: read internal: %v", key, err)
		}
		section := internal
		if i := strings.IndexByte(internal, '.'); i >= 0 {
			section = internal[:i]
		}
		if secL, ok := sectionLayer[section]; ok && secL != layer {
			t.Errorf("field %q: derived layer %q contradicts section %q (layer %q)", key, layer, section, secL)
		}

		// Only a CP-observed fact may be declaration-hardened: you cannot check an
		// observation that was never made.
		hardened, err := entry.LookupPath(cue.ParsePath("hardenedByDeclaration")).Bool()
		if err != nil {
			t.Fatalf("field %q: read hardenedByDeclaration: %v", key, err)
		}
		if hardened && prov != "cpObserved" {
			t.Errorf("field %q: hardenedByDeclaration=true requires provenance cpObserved, got %q", key, prov)
		}
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
		t.Errorf("%s field set disagrees with meta-trust-layers.cue:\n  got:  %v\n  want: %v",
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
