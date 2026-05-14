// Package probe wraps filesystem-probing primitives at a named
// chokepoint so that gosec suppressions for env-supplied paths live
// once, at the package boundary, instead of at every caller.
//
// The package is intentionally minimal. A new exported symbol
// requires at least two call sites that benefit from it.
package probe

import "os"

// Stat returns os.Stat(path). The function adds no behaviour; its
// purpose is to hold the G703 suppression at a single named site.
// The package contract is that the path is env-supplied bootstrap
// discovery (socket paths, $KUBECONFIG, well-known config
// locations) where path confinement does not apply -- the question
// being answered is *which root to use*, not "is name under root".
//
// Callers that need only existence test err == nil. Callers that
// need mode bits or other file metadata use the returned FileInfo.
// Callers that propagate the stat error wrap err directly.
func Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}
