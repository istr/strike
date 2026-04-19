package container_test

import (
	"fmt"
	"testing"
)

// navPath walks a JSON-decoded map tree along the given key path.
// Returns the value at the path and true, or nil and false if any
// intermediate key is missing or not a map.
func navPath(m map[string]any, path ...string) (any, bool) {
	cur := any(m)
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := mm[k]
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// jsonEqual compares a value decoded from raw JSON (where numbers
// arrive as float64, arrays as []any, objects as map[string]any)
// against a value produced by the typed decoder. Scalars compare
// directly; everything else falls back to fmt-based comparison,
// which is sufficient for drift detection.
func jsonEqual(raw, typed any) bool {
	switch t := typed.(type) {
	case bool:
		r, ok := raw.(bool)
		return ok && r == t
	case string:
		r, ok := raw.(string)
		return ok && r == t
	case int:
		r, ok := raw.(float64)
		return ok && int(r) == t
	case int64:
		r, ok := raw.(float64)
		return ok && int64(r) == t
	case float64:
		r, ok := raw.(float64)
		return ok && r == t
	default:
		return fmt.Sprintf("%v", raw) == fmt.Sprintf("%v", typed)
	}
}

// diffCheck is a single field comparison for a drift test.
type diffCheck struct {
	field string   // typed field name for diagnostics, e.g. "State.Running"
	got   any      // value produced by the typed decoder
	path  []string // JSON path into the raw response
}

// runDriftChecks executes all checks as named subtests. Each failure
// names both sides so the drifting field is identifiable at a glance.
func runDriftChecks(t *testing.T, m map[string]any, checks []diffCheck) {
	t.Helper()
	for _, c := range checks {
		t.Run(c.field, func(t *testing.T) {
			raw, ok := navPath(m, c.path...)
			if !ok {
				t.Fatalf("raw response missing path %v -- schema drift?", c.path)
			}
			if !jsonEqual(raw, c.got) {
				t.Errorf("typed %s = %v (%T), raw %v = %v (%T) -- schema drift?",
					c.field, c.got, c.got,
					joinPath(c.path), raw, raw)
			}
		})
	}
}

func joinPath(p []string) string {
	out := ""
	for i, s := range p {
		if i > 0 {
			out += "."
		}
		out += s
	}
	return out
}
