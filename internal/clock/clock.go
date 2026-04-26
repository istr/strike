// Package clock is the single sanctioned source of wall-clock,
// duration, and time-type access in strike. All other packages must
// import clock; direct imports of the standard library "time" package
// are forbidden by depguard outside this file.
//
// Rationale: design principle "Reproducibility is enforced, not hoped
// for" requires that values affecting artifact content bytes come
// from a deterministic source (SOURCE_DATE_EPOCH). Making "time"
// reachable only through this package turns the principle from a
// code-review convention into a structural invariant checked in CI.
package clock

import (
	"os"
	"strconv"
	"time"
)

// Time is an alias for time.Time so call sites do not need to import "time".
type Time = time.Time

// Duration is an alias for time.Duration so call sites do not need to import "time".
type Duration = time.Duration

// Duration constants re-exported for step timeouts, test certificate
// validity windows, and log rounding.
const (
	Nanosecond  = time.Nanosecond
	Microsecond = time.Microsecond
	Millisecond = time.Millisecond
	Second      = time.Second
	Minute      = time.Minute
	Hour        = time.Hour
)

// Format layout constants. RFC3339 ("2006-01-02T15:04:05Z07:00") is
// the sanctioned layout for external-facing timestamp serialization
// (SBOM metadata, attestation fields, log lines that need to be
// machine-readable).
const (
	RFC3339 = time.RFC3339
)

// Wall returns the current wall-clock time. Use for:
//   - deploy attestation timestamps (event receipts: signed, but not
//     claimed to be reproducible across runs)
//   - audit log timestamps and duration start points
//   - engine handshake timestamps
//   - test fixtures with short validity windows
//
// Do NOT use for any value whose bytes end up in artifact content.
// For that, use Reproducible().
func Wall() Time {
	return time.Now()
}

// Reproducible returns the time to stamp into reproducible artifact
// content. Reads SOURCE_DATE_EPOCH; defaults to Unix epoch 0 in UTC
// when unset or malformed. The return value never depends on when
// strike runs, only on its input environment.
func Reproducible() Time {
	if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return Unix(n, 0).UTC()
		}
	}
	return Unix(0, 0).UTC()
}

// Since returns the wall-clock duration elapsed since t. Thin wrapper
// so callers measuring an interval do not need to import "time".
func Since(t Time) Duration {
	return time.Since(t)
}

// Unix converts a Unix timestamp to Time. Use when parsing external
// timestamps (Rekor inclusion time, OCI image-config "created", etc.).
func Unix(sec, nsec int64) Time {
	return time.Unix(sec, nsec)
}

// ParseDuration parses a duration string such as "30s", "5m", "1h30m".
// Deterministic: same input, same output. Safe to use in any code
// path, including those that feed artifact content.
func ParseDuration(s string) (Duration, error) {
	return time.ParseDuration(s)
}
