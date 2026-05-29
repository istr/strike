// Package copier provides full- and half-duplex byte forwarding with
// expected-close filtering. Intended for socket-forwarding goroutines
// (typical SSH-agent shape) where io.Copy returns "use of closed
// connection" on shutdown and that is not a real failure.
package copier

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

// Forward copies src->dst, then half-closes dst if it supports
// CloseWrite. Both io.Copy and CloseWrite errors are logged at WARN
// unless they are expected-close conditions.
func Forward(dst io.Writer, src io.Reader, context string) {
	if _, err := io.Copy(dst, src); err != nil && !IsExpectedClose(err) {
		log.Printf("WARN   %s: copy: %v", context, err)
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil && !IsExpectedClose(err) {
			log.Printf("WARN   %s: half-close: %v", context, err)
		}
	}
}

// IsExpectedClose reports whether err is an expected socket-shutdown
// condition (EOF, closed connection, broken pipe, reset).
func IsExpectedClose(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return true
	}
	// string-based fallback: stdlib does not wrap all underlying conditions
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset by peer")
}
