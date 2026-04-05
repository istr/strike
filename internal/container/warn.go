package container

import (
	"io"
	"log"
)

// warnClose closes c and logs a warning on failure.
// Use for best-effort cleanup where errors indicate environmental
// problems (socket failure, filesystem issues) that should be
// visible in audit logs but are not actionable by the caller.
func warnClose(c io.Closer, context string) {
	if err := c.Close(); err != nil {
		log.Printf("WARN   %s: close: %v", context, err)
	}
}
