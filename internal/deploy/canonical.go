// Canonical JSON for the signing path.
//
// canonicalJSON serializes a value to JSON whose byte sequence is independent
// of Go struct field declaration order, so the signed statement bytes and the
// recorded attestation digest stay stable across field reordering (including
// the eventual migration from hand-written to generated DTOs) and can be
// reproduced by a verifier written in any language. It implements the subset of
// RFC 8785 (JSON Canonicalization Scheme) that strike's signed payloads
// exercise: objects, arrays, strings, and the literals true/false/null. The
// payloads carry no numbers -- the signed graph has no numeric fields, asserted
// by TestSignedGraphNoNumbers -- so the scheme's number formatting is
// intentionally absent: a number is a contract violation and is rejected.
// Object keys are emitted in ascending byte order; every key in the signed
// graph is ASCII (in-toto and SLSA field names, and primitive.Identifier map
// keys, which are lowercase ASCII), for which byte order is identical to RFC
// 8785's UTF-16 code-unit ordering. Strings use the minimal escaping RFC 8785
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
		return fmt.Errorf("canonical json: numbers are not supported in the signed payload, got %q", t.String())
	case []any:
		return writeArray(buf, t)
	case map[string]any:
		return writeObject(buf, t)
	default:
		return fmt.Errorf("canonical json: unsupported type %T", v)
	}
	return nil
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
