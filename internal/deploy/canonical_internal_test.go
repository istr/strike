package deploy

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestCanonicalJSON pins the encoder properties the signing path relies on:
// key-order independence, RFC 8785 minimal string escaping (no HTML escaping),
// literal handling, the one admitted form of number, and rejection of every
// other number and of a key outside ASCII.
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

	for _, n := range []string{"0", "7", "123456789012345"} {
		t.Run("integer_"+n, func(t *testing.T) {
			got, intErr := canonicalJSON(map[string]any{"n": json.Number(n)})
			if intErr != nil {
				t.Fatalf("canonicalJSON: %v", intErr)
			}
			if want := `{"n":` + n + `}`; string(got) != want {
				t.Errorf("got %s, want %s", got, want)
			}
		})
	}

	for _, n := range []string{"-1", "1.5", "1e2", "1234567890123456"} {
		t.Run("number_"+n, func(t *testing.T) {
			if _, numErr := canonicalJSON(map[string]any{"n": json.Number(n)}); numErr == nil {
				t.Errorf("expected an error on the number %s", n)
			}
		})
	}

	if _, keyErr := canonicalJSON(map[string]any{"\u00e9": "x"}); keyErr == nil {
		t.Error("expected an error on a key outside ASCII")
	}
}

// TestSignedGraphNoNumbers asserts the in-toto statements and the internal
// attestation carry no numeric fields. canonicalJSON admits only a plain
// non-negative integer, so a numeric field would either fail the signing path
// closed at runtime or put a number into a statement; this guard surfaces it
// at test time as a deliberate decision point. Fields excluded from
// JSON (json:"-") and unexported fields are skipped; a []byte (including
// json.RawMessage) serializes to a base64 string, not numbers, and is not a
// violation. Union types reached through an interface are not traversed here;
// their concrete records marshal to string-only JSON. A type that implements
// json.Marshaler is not traversed either: its MarshalJSON, not its field
// layout, decides the JSON it emits, so a numeric field inside it never
// reaches the signed bytes as a number (endpoint.Address holds a numeric port
// and marshals to one URL string). Such a type proves its string-only output
// in its own tests, and canonicalJSON still fails the signing path closed if
// a MarshalJSON ever emits a number other than that integer.
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
	if typ.Implements(reflect.TypeFor[json.Marshaler]()) {
		return // MarshalJSON, not the field layout, decides the JSON form
	}
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
