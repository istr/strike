// Package copier provides full- and half-duplex byte forwarding with
// expected-close filtering. Intended for socket-forwarding goroutines
// (typical SSH-agent shape) where io.Copy returns "use of closed
// connection" on shutdown and that is not a real failure.
package copier

import (
	"io"
	"log"

	"github.com/istr/strike/internal/closer"
)

// Forward copies src->dst, then half-closes dst if it supports
// CloseWrite. Both io.Copy and CloseWrite errors are logged at WARN
// unless they are expected-close conditions.
func Forward(dst io.Writer, src io.Reader, context string) {
	if _, err := io.Copy(dst, src); err != nil && !closer.IsExpectedClose(err) {
		log.Printf("WARN   %s: copy: %v", context, err)
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil && !closer.IsExpectedClose(err) {
			log.Printf("WARN   %s: half-close: %v", context, err)
		}
	}
}
