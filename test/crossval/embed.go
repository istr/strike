// Package crossval embeds the language-independent test vectors
// at test/crossval/*. It is consumed by Go test code to load the
// vectors hermetically; the vectors are also read by the future
// Rust verifier directly from disk.
package crossval

import "embed"

// FS holds every file under test/crossval/ (this directory).
//
//go:embed *
var FS embed.FS
