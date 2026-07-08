package deploy

import (
	"reflect"
	"testing"
)

// TestCanonicalJSON pins the encoder properties the signing path relies on:
// key-order independence, RFC 8785 minimal string escaping (no HTML escaping),
// literal handling, and rejection of numbers.
func TestCanonicalJSON(t *testing.T) {
	keyOrder, err := canonicalJSON(map[string]any{"b": "2", "a": "1", "c": "3"})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if got := string(keyOrder); got != `{"a":"1","b":"2","c":"3"}` {
		t.Errorf("key order not canonical: %s", got)
	}

	escaped, err := canonicalJSON(map[string]any{"u": "a<b>&\"\\\t"})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if got := string(escaped); got != `{"u":"a<b>&\"\\\t"}` {
		t.Errorf("string escaping wrong: %s", got)
	}

	literals, err := canonicalJSON(map[string]any{"t": true, "f": false, "n": nil})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if got := string(literals); got != `{"f":false,"n":null,"t":true}` {
		t.Errorf("literals wrong: %s", got)
	}

	if _, numErr := canonicalJSON(map[string]any{"n": 1}); numErr == nil {
		t.Error("expected an error on a numeric value")
	}
}

// TestSignedGraphNoNumbers asserts the in-toto statements and the internal
// attestation carry no numeric fields. canonicalJSON rejects numbers, so a
// numeric field would make the signing path fail closed at runtime; this guard
// surfaces it at test time as a deliberate decision point. Fields excluded from
// JSON (json:"-") and unexported fields are skipped; a []byte (including
// json.RawMessage) serializes to a base64 string, not numbers, and is not a
// violation. Union types reached through an interface are not traversed here;
// their concrete records are string-only by construction.
func TestSignedGraphNoNumbers(t *testing.T) {
	roots := []reflect.Type{
		reflect.TypeOf(SLSAProvenanceStatement{}),
		reflect.TypeOf(EngineContextStatement{}),
		reflect.TypeOf(InformationalStatement{}),
		reflect.TypeOf(Attestation{}),
	}
	seen := map[reflect.Type]bool{}
	for _, r := range roots {
		assertNoNumeric(t, r, r.Name(), seen)
	}
}

func assertNoNumeric(t *testing.T, typ reflect.Type, path string, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[typ] {
		return
	}
	seen[typ] = true
	switch typ.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		t.Errorf("numeric field reaches the signed graph at %s (%s)", path, typ.Kind())
	case reflect.Pointer:
		assertNoNumeric(t, typ.Elem(), path, seen)
	case reflect.Slice, reflect.Array:
		if typ.Elem().Kind() == reflect.Uint8 {
			return // []byte / json.RawMessage -> JSON string, not numbers
		}
		assertNoNumeric(t, typ.Elem(), path+"[]", seen)
	case reflect.Map:
		assertNoNumeric(t, typ.Key(), path+".key", seen)
		assertNoNumeric(t, typ.Elem(), path+".val", seen)
	case reflect.Struct:
		for i := range typ.NumField() {
			f := typ.Field(i)
			if f.PkgPath != "" {
				continue // unexported: not marshaled
			}
			if f.Tag.Get("json") == "-" {
				continue // explicitly excluded from JSON
			}
			assertNoNumeric(t, f.Type, path+"."+f.Name, seen)
		}
	}
}
