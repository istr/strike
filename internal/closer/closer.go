// Package closer provides error-consuming wrappers for the standard
// "best-effort cleanup" idiom used in defer statements.
//
// Cleanup failures (Close on a file or socket, RemoveAll on a scratch
// directory) are real environmental signals and are logged at WARN.
// They are never returned, because by construction the call sites are
// deferred and have no return slot.
package closer

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

// Warn closes c. On failure it logs a WARN with the given context, unless the
// failure is an expected socket/stream-shutdown condition (see
// IsExpectedClose) -- those are normal teardown, not environmental signals.
// A real close failure (e.g. ENOSPC on a file flush, fd table corruption)
// still warns.
func Warn(c io.Closer, context string) {
	if err := c.Close(); err != nil && !IsExpectedClose(err) {
		log.Printf("WARN   %s: close: %v", context, err)
	}
}

// IsExpectedClose reports whether err is an expected socket/stream-shutdown
// condition: EOF, a closed connection or file, a broken pipe, or a peer reset.
// These occur routinely when one side of a duplex stream tears down before the
// other and are not failures. Anything else (permission denied, no space,
// etc.) is a real error and is not classified as expected.
func IsExpectedClose(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return true
	}
	// stdlib does not wrap all underlying conditions; fall back to string match.
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset by peer")
}

// Remove deletes path with os.RemoveAll. On failure it logs a WARN
// with the given context.
func Remove(path, context string) {
	if err := os.RemoveAll(path); err != nil {
		log.Printf("WARN   %s: remove %s: %v", context, path, err)
	}
}
