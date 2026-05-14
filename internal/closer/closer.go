// Package closer provides error-consuming wrappers for the standard
// "best-effort cleanup" idiom used in defer statements.
//
// Cleanup failures (Close on a file or socket, RemoveAll on a scratch
// directory) are real environmental signals and are logged at WARN.
// They are never returned, because by construction the call sites are
// deferred and have no return slot.
package closer

import (
	"io"
	"log"
	"os"
)

// Warn closes c. On failure it logs a WARN with the given context.
func Warn(c io.Closer, context string) {
	if err := c.Close(); err != nil {
		log.Printf("WARN   %s: close: %v", context, err)
	}
}

// Remove deletes path with os.RemoveAll. On failure it logs a WARN
// with the given context.
func Remove(path, context string) {
	if err := os.RemoveAll(path); err != nil {
		log.Printf("WARN   %s: remove %s: %v", context, path, err)
	}
}
