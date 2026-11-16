package deploy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/primitive"
)

// TestRenderCycloneDXCanonical pins the byte form of a CycloneDX document
// (ADR-059 D2 and D7): canonical bytes, specification version 1.7 with the
// matching schema, version 1, and a serial number that is the UUIDv8 of the
// canonical document without it.
func TestRenderCycloneDXCanonical(t *testing.T) {
	components := []component{{
		Name:      "libc6",
		Version:   "2.36-9",
		PURL:      "pkg:deb/debian/libc6@2.36-9?arch=amd64",
		Ecosystem: "deb",
	}}
	subject := primitive.Digest("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	doc, err := renderCycloneDX(components, subject, clock.Unix(1700000000, 0).UTC())
	if err != nil {
		t.Fatalf("renderCycloneDX: %v", err)
	}

	again, err := canonicalize(doc)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !bytes.Equal(again, doc) {
		t.Errorf("document is not in canonical form:\n%s", doc)
	}

	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var fields map[string]any
	if decErr := dec.Decode(&fields); decErr != nil {
		t.Fatalf("decode: %v", decErr)
	}

	for _, tc := range []struct {
		want any
		key  string
	}{
		{key: "$schema", want: "http://cyclonedx.org/schema/bom-1.7.schema.json"},
		{key: "bomFormat", want: "CycloneDX"},
		{key: "specVersion", want: "1.7"},
		{key: "version", want: json.Number("1")},
	} {
		t.Run(tc.key, func(t *testing.T) {
			if got := fields[tc.key]; got != tc.want {
				t.Errorf("%s = %v, want %v", tc.key, got, tc.want)
			}
		})
	}

	t.Run("serialNumber", func(t *testing.T) {
		serial, ok := fields["serialNumber"].(string)
		if !ok {
			t.Fatalf("serialNumber missing or not a string: %v", fields["serialNumber"])
		}
		delete(fields, "serialNumber")
		unnamed, cErr := canonicalJSON(fields)
		if cErr != nil {
			t.Fatalf("canonicalJSON: %v", cErr)
		}
		if want := contentUUID(unnamed); serial != want {
			t.Errorf("serialNumber = %s, want %s", serial, want)
		}
		if !strings.HasPrefix(serial, "urn:uuid:") || len(serial) != 45 || serial[23] != '8' || !strings.ContainsRune("89ab", rune(serial[28])) {
			t.Errorf("serialNumber %s is not a UUIDv8 URN", serial)
		}
	})
}
