package registry

import (
	"io"
	"log"
	"os"
)

// warnClose closes c and logs a warning to stderr on failure.
func warnClose(c io.Closer, context string) {
	if err := c.Close(); err != nil {
		log.Printf("WARN   %s: close: %v", context, err)
	}
}

// warnRemoveAll removes dir and logs a warning on failure.
func warnRemoveAll(dir, context string) {
	if err := os.RemoveAll(dir); err != nil {
		log.Printf("WARN   %s: cleanup: %v", context, err)
	}
}
