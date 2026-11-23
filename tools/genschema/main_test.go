package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// openTree writes files below a new temporary directory and opens it as a
// root.
func openTree(t *testing.T, files map[string]string) *os.Root {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tree, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := tree.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	return tree
}

const placedCUE = `package p

import "struct"

#Root: {
	ref?: #T & struct.MinFields(1)
	m?: {[string]: string} & struct.MinFields(2)
	nested: {
		inner?: #T & struct.MinFields(1)
	}
	plain?: #T
	paren?: (#T & struct.MinFields(1))
}

#T: {
	x?: string
}

#Other: close({
	o?: #T & struct.MinFields(3)
	if true {
		c?: #T & struct.MinFields(1)
	}
	{
		e?: #T & struct.MinFields(1)
	}
})

#Unexported: {
	u?: #T & struct.MinFields(1)
}
`

const placedSchema = `{
  "description": "a <b> -> c",
  "type": "object",
  "properties": {
    "ref": {"$ref": "#/$defs/T"},
    "m": {"type": "object", "additionalProperties": {"type": "string"}},
    "nested": {"type": "object", "properties": {"inner": {"$ref": "#/$defs/T"}}},
    "plain": {"$ref": "#/$defs/T"},
    "paren": {"$ref": "#/$defs/T"}
  },
  "$defs": {
    "T": {"type": "object", "maxProperties": 7},
    "Other": {"type": "object", "properties": {"o": {"$ref": "#/$defs/T"}, "c": {"$ref": "#/$defs/T"}, "e": {"$ref": "#/$defs/T"}}}
  }
}
`

const untouchedSchema = `{"$defs": {"T": {"type": "object"}}, "description": "a <b>"}
`

// TestRunPlacesSites places every site the CUE source carries -- beside a
// $ref, in an inline object, in a nested struct, in parentheses, in a closed
// definition, in a comprehension and in an embedding -- and leaves a field without one, a
// definition no export holds, and an export without a site alone.
func TestRunPlacesSites(t *testing.T) {
	tree := openTree(t, map[string]string{
		"p/p.cue":   placedCUE,
		"a.json":    placedSchema,
		"b.json":    untouchedSchema,
		"notes.txt": "not CUE",
	})
	if err := run(tree, []string{"a.json=#Root", "b.json=#T"}); err != nil {
		t.Fatal(err)
	}
	b, err := tree.ReadFile("b.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != untouchedSchema {
		t.Errorf("b.json was rewritten:\n%s", b)
	}
	a, err := tree.ReadFile("a.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\n    \"$defs\": {\n", "a <b> -> c", "\"maxProperties\": 7"} {
		if !strings.Contains(string(a), want) {
			t.Errorf("a.json does not contain %q:\n%s", want, a)
		}
	}
	var doc map[string]any
	if err = json.Unmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		want any
		path []string
	}{
		{float64(1), []string{"properties", "ref"}},
		{float64(2), []string{"properties", "m"}},
		{float64(1), []string{"properties", "nested", "properties", "inner"}},
		{nil, []string{"properties", "plain"}},
		{float64(1), []string{"properties", "paren"}},
		{nil, []string{"$defs", "T"}},
		{float64(3), []string{"$defs", "Other", "properties", "o"}},
		{float64(1), []string{"$defs", "Other", "properties", "c"}},
		{float64(1), []string{"$defs", "Other", "properties", "e"}},
	} {
		node := doc
		for _, name := range tc.path {
			node = object(node[name])
		}
		if got := node["minProperties"]; got != tc.want {
			t.Errorf("%s: minProperties = %v, want %v", strings.Join(tc.path, "."), got, tc.want)
		}
	}
}

// TestRunRejects fails the generation for every struct.MinFields that is not a
// site, for a site whose place an export lacks or whose definition two
// packages declare, and for an argument, an export or a CUE file it cannot
// read.
func TestRunRejects(t *testing.T) {
	const head = "package p\n\nimport \"struct\"\n\n"
	const schema = `{"type": "object", "properties": {"a": {"$ref": "#/$defs/T"}}, "$defs": {"T": {"type": "object"}}}`
	tests := []struct {
		files map[string]string
		name  string
		arg   string
		want  string
	}{
		{
			name:  "definition value",
			files: map[string]string{"p/p.cue": head + "#T: {x?: string} & struct.MinFields(1)\n"},
			want:  "struct.MinFields is not a site",
		},
		{
			name:  "pattern constraint",
			files: map[string]string{"p/p.cue": head + "#T: {[string]: {x?: string} & struct.MinFields(1)}\n"},
			want:  "struct.MinFields is not a site",
		},
		{
			name:  "list element",
			files: map[string]string{"p/p.cue": head + "#T: {l?: [{x?: string} & struct.MinFields(1)]}\n"},
			want:  "struct.MinFields is not a site",
		},
		{
			name:  "minimum with two arguments",
			files: map[string]string{"p/p.cue": head + "#T: {a?: {x?: string} & struct.MinFields(1, 2)}\n"},
			want:  "struct.MinFields is not a site",
		},
		{
			name:  "minimum not a literal",
			files: map[string]string{"p/p.cue": head + "n: 1\n#T: {a?: {x?: string} & struct.MinFields(n)}\n"},
			want:  "struct.MinFields is not a site",
		},
		{
			name:  "definition in two packages",
			files: map[string]string{"p/p.cue": head + "#T: {a?: {x?: string} & struct.MinFields(1)}\n", "q/q.cue": "package q\n\n#T: {x?: string}\n"},
			want:  "#T is declared in the packages p, q",
		},
		{
			name:  "field missing from the export",
			files: map[string]string{"p/p.cue": head + "#Root: {gone?: {x?: string} & struct.MinFields(1)}\n", "a.json": schema},
			arg:   "a.json=#Root",
			want:  "the export has no schema for the field gone",
		},
		{
			name:  "properties missing from the export",
			files: map[string]string{"p/p.cue": head + "#Root: {a: {b?: {x?: string} & struct.MinFields(1)}}\n", "a.json": schema},
			arg:   "a.json=#Root",
			want:  "the export has no properties above the field b",
		},
		{
			name:  "argument without a definition",
			files: map[string]string{"a.json": schema},
			arg:   "a.json",
			want:  "want <schema file>=#<definition>",
		},
		{
			name:  "export missing",
			files: map[string]string{"p/p.cue": head},
			arg:   "none.json=#Root",
			want:  "none.json",
		},
		{
			name:  "export not JSON",
			files: map[string]string{"a.json": "{"},
			arg:   "a.json=#Root",
			want:  "a.json: unexpected EOF",
		},
		{
			name:  "CUE syntax",
			files: map[string]string{"p/p.cue": "package p\n\n#T: {\n"},
			want:  "p/p.cue",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			if tc.arg != "" {
				args = []string{tc.arg}
			}
			err := run(openTree(t, tc.files), args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// TestRunRejectsUnreadableCUE fails the generation on a CUE file it cannot
// read, here a link to nothing.
func TestRunRejectsUnreadableCUE(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("nowhere.cue", filepath.Join(dir, "broken.cue")); err != nil {
		t.Fatal(err)
	}
	tree, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := tree.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	if err = run(tree, nil); err == nil || !strings.Contains(err.Error(), "broken.cue") {
		t.Fatalf("err = %v, want an error naming broken.cue", err)
	}
}
