// Canonical JSON for the signing path.
//
// canonicalJSON serializes a value to JSON whose byte sequence is independent
// of Go struct field declaration order, so the signed statement bytes and the
// recorded attestation digest stay stable across field reordering (including
// the eventual migration from hand-written to generated DTOs) and can be
// reproduced by a verifier written in any language. It implements the subset of
// RFC 8785 (JSON Canonicalization Scheme) that strike's published payloads
// exercise: objects, arrays, strings, the literals true/false/null, and one form
// of number, a non-negative integer of at most 15 digits written as its plain
// digits (ADR-059 D2). That is the RFC 8785 form of such an integer, so the
// scheme's number formatting is not needed; every other number is a contract
// violation and is rejected. The integer is the version of a CycloneDX
// document, which reaches a statement only as the predicate of the SBOM
// statement. The fields strike defines carry no numbers -- asserted by
// TestSignedGraphNoNumbers, and a type with its own MarshalJSON (such as
// endpoint.Address, whose numeric port marshals inside one URL string) emits
// none.
// Object keys must be ASCII and are emitted in ascending byte order, which for
// ASCII is identical to RFC 8785's UTF-16 code-unit ordering; a key outside
// ASCII is rejected. Strings use the minimal escaping RFC 8785
// mandates: the two mandatory escapes, the five short control escapes, lowercase
// \u00xx for the remaining C0 controls, and every other rune literal -- no HTML
// escaping.

package deploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// canonicalJSON marshals v and re-serializes it in canonical form. It is the
// signing-path replacement for json.Marshal: the DSSE signature and the
// recorded attestation digest are taken over these bytes, so they must not
// depend on Go struct field order.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canonicalize(raw)
}

// canonicalize re-serializes one JSON value in canonical form. It takes bytes
// a library marshaled, such as a CycloneDX document: the library decides names,
// structure and omission, and the byte form is strike's (ADR-059 D2).
func canonicalize(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if decErr := dec.Decode(&tree); decErr != nil {
		return nil, fmt.Errorf("canonical json: decode: %w", decErr)
	}
	var buf bytes.Buffer
	if writeErr := writeCanonical(&buf, tree); writeErr != nil {
		return nil, writeErr
	}
	return buf.Bytes(), nil
}

// writeCanonical emits one decoded value in canonical form. The dynamic type is
// one of: nil, bool, string, json.Number, []any, or map[string]any.
func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		writeBool(buf, t)
	case string:
		writeCanonicalString(buf, t)
	case json.Number:
		if !isCanonicalInteger(t.String()) {
			return fmt.Errorf("canonical json: only a non-negative integer of at most 15 digits is supported, got %q", t.String())
		}
		buf.WriteString(t.String())
	case []any:
		return writeArray(buf, t)
	case map[string]any:
		return writeObject(buf, t)
	default:
		return fmt.Errorf("canonical json: unsupported type %T", v)
	}
	return nil
}

// isCanonicalInteger reports whether s is a non-negative integer written as its
// plain digits: "0", or a digit from 1 to 9 followed by at most 14 digits.
// Every such integer is below 2^53, so these digits are its RFC 8785 form.
func isCanonicalInteger(s string) bool {
	if s == "0" {
		return true
	}
	if len(s) == 0 || len(s) > 15 || s[0] < '1' || s[0] > '9' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func writeBool(buf *bytes.Buffer, b bool) {
	if b {
		buf.WriteString("true")
		return
	}
	buf.WriteString("false")
}

func writeArray(buf *bytes.Buffer, a []any) error {
	buf.WriteByte('[')
	for i, e := range a {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonical(buf, e); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

func writeObject(buf *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf.WriteByte('{')
	for i, k := range keys {
		for j := range len(k) {
			if k[j] > 0x7f {
				return fmt.Errorf("canonical json: key %q is outside ASCII", k)
			}
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		writeCanonicalString(buf, k)
		buf.WriteByte(':')
		if err := writeCanonical(buf, m[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				const hexDigits = "0123456789abcdef"
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[r>>4])
				buf.WriteByte(hexDigits[r&0xf])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
