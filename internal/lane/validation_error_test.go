package lane_test

import (
	"errors"
	"strings"
	"testing"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"

	"github.com/istr/strike/internal/lane"
)

func TestFormatValidationError_Nil(t *testing.T) {
	if got := lane.FormatValidationError(nil); got != nil {
		t.Errorf("FormatValidationError(nil) = %v, want nil", got)
	}
}

func TestFormatValidationError_PlainErrorPassthrough(t *testing.T) {
	plain := errors.New("not a cue error")
	got := lane.FormatValidationError(plain)
	if got == nil || got.Error() != "not a cue error" {
		t.Errorf("FormatValidationError(plain) = %v, want passthrough", got)
	}
}

// TestFormatValidationError_DropsDisjunctionMarker compiles a tiny
// disjunction schema and validates a value that fails every branch.
// The raw cue.Error contains the "N errors in empty disjunction"
// marker plus N concrete sub-errors; the formatter must keep the
// concrete sub-errors and drop the marker line.
func TestFormatValidationError_DropsDisjunctionMarker(t *testing.T) {
	ctx := cuecontext.New()
	schema := ctx.CompileString(`
		#Color: {kind: "rgb", r: int, g: int, b: int} |
		        {kind: "named", name: string}
	`).LookupPath(cue.ParsePath("#Color"))
	if schema.Err() != nil {
		t.Fatalf("compile schema: %v", schema.Err())
	}

	bad := ctx.CompileString(`{kind: "wrong"}`)
	unified := schema.Unify(bad)
	rawErr := unified.Validate(cue.Concrete(true))
	if rawErr == nil {
		t.Fatal("expected a validation error from the disjunction")
	}

	// Sanity: the raw error contains the marker phrase.
	if !strings.Contains(rawErr.Error(), "empty disjunction") {
		t.Logf("raw error did not contain disjunction marker -- CUE may have changed its rendering: %v", rawErr)
	}

	formatted := lane.FormatValidationError(rawErr)
	if formatted == nil {
		t.Fatal("FormatValidationError returned nil for a real error")
	}
	if strings.Contains(formatted.Error(), "errors in empty disjunction") {
		t.Errorf("formatter did not drop disjunction marker: %v", formatted)
	}
	// Must still contain at least one concrete sub-error.
	if !strings.Contains(formatted.Error(), "kind") {
		t.Errorf("formatter dropped too much; expected mention of 'kind': %v", formatted)
	}
}

// TestFormatValidationError_Dedupe constructs a synthetic cue.Error
// list with duplicated messages by validating a value that triggers
// the same constraint at two paths. The formatter must collapse
// duplicates.
func TestFormatValidationError_Dedupe(t *testing.T) {
	ctx := cuecontext.New()
	schema := ctx.CompileString(`
		#Pair: {a: string, b: string}
	`).LookupPath(cue.ParsePath("#Pair"))
	if schema.Err() != nil {
		t.Fatalf("compile schema: %v", schema.Err())
	}

	bad := ctx.CompileString(`{a: 1, b: 2}`)
	unified := schema.Unify(bad)
	rawErr := unified.Validate(cue.Concrete(true))
	if rawErr == nil {
		t.Fatal("expected validation error")
	}

	formatted := lane.FormatValidationError(rawErr)
	if formatted == nil {
		t.Fatal("FormatValidationError returned nil")
	}

	// Each line should be unique.
	lines := strings.Split(formatted.Error(), "\n")
	seen := make(map[string]int, len(lines))
	for _, l := range lines {
		seen[l]++
		if seen[l] > 1 {
			t.Errorf("duplicate line in formatted error: %q\nfull output:\n%s", l, formatted.Error())
		}
	}
}
