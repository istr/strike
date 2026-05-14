// Package testutil provides test-only helpers for cleanup, HTTP
// response writing, file I/O, and echo-socket scaffolding.
package testutil

import (
	"io"
	"testing"
)

// CloseLog closes c and logs via t.Logf on failure.
func CloseLog(t *testing.T, c io.Closer, context string) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Logf("%s: close: %v", context, err)
	}
}
