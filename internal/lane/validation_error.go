package lane

import (
	"errors"
	"fmt"
	"strings"

	cueerrors "cuelang.org/go/cue/errors"
)

// FormatValidationError flattens a cue.Error tree into a deduplicated
// multi-line string, dropping the "N errors in empty disjunction"
// aggregate markers that hide the underlying sub-errors.
//
// Returns nil if err is nil. Returns the original err if it is not a
// cue.Error (for example, a plain extraction error from
// cuejson.Extract before any schema unification ran).
//
// Stage 1: aggregates and dedupes. Per-branch filtering using the
// discriminator value is deferred to stage 2.
func FormatValidationError(err error) error {
	if err == nil {
		return nil
	}

	cueErrs := cueerrors.Errors(err)
	if len(cueErrs) == 0 {
		// Not a cue.Error tree -- pass through unchanged.
		return err
	}

	var lines []string
	seen := make(map[string]struct{}, len(cueErrs))
	for _, e := range cueErrs {
		msg := e.Error()
		// Skip the synthetic aggregate marker that CUE emits for
		// disjunction failure. The interesting information is in
		// the sub-errors that follow it in the slice.
		if isDisjunctionMarker(msg) {
			continue
		}
		if _, dup := seen[msg]; dup {
			continue
		}
		seen[msg] = struct{}{}
		lines = append(lines, msg)
	}

	if len(lines) == 0 {
		// Every entry was a marker -- fall back to the original
		// rendering so the user is not handed an empty error.
		return err
	}

	return errors.New(strings.Join(lines, "\n"))
}

// isDisjunctionMarker recognises the aggregate text that CUE emits
// when a disjunction has no successful branch. The exact phrasing is
// stable across cuelang.org/go v0.16.x; if it changes in a future
// release, the marker leaks back into output as a low-priority
// regression rather than as silent corruption.
func isDisjunctionMarker(msg string) bool {
	return strings.Contains(msg, "errors in empty disjunction") ||
		strings.Contains(msg, "empty disjunction:")
}

// Compile-time guard: cueerrors.Errors must accept a plain error.
// Documented behaviour, but worth pinning so a dependency upgrade
// that changed the signature would surface here.
var _ = func() error {
	return cueerrors.Errors(fmt.Errorf("plain"))[0]
}
