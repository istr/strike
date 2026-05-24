package lane

import (
	"fmt"
	"path"
	"strings"
)

// SymlinkEscapes reports whether a symlink located at linkRel -- a
// slash-separated path relative to a containment root -- with the given
// target would resolve outside that root. Evaluation is purely lexical: no
// filesystem is touched, so the result depends only on the two strings.
//
// An absolute target always escapes: no strike mountpoint is rooted at
// "/", so an absolute target can never be contained. A relative target may
// use ".." freely as long as the net resolved path stays within the root.
//
// linkRel is the link itself (e.g. "node_modules/website"); target is its
// verbatim value (e.g. "../packages/hugoautogen", which resolves to
// "packages/hugoautogen" -- contained -- when the root holds both).
func SymlinkEscapes(linkRel, target string) bool {
	if path.IsAbs(target) {
		return true
	}
	resolved := path.Join(path.Dir(linkRel), target)
	return resolved == ".." || strings.HasPrefix(resolved, "../")
}

// SymlinkContainmentError reports the containment of a symlink as an error:
// nil when target stays within the subtree rooted where linkRel lives, and a
// diagnostic error when it escapes. frame names that subtree in the message
// ("output tree" for an output projection, "mount tree" for an input mount).
// This is the single reject-and-diagnostic used by every containment site --
// the output canonicalizer and the input mount walk -- so the policy and its
// wording stay identical across produce and consume.
func SymlinkContainmentError(linkRel, target, frame string) error {
	if SymlinkEscapes(linkRel, target) {
		return fmt.Errorf("symlink %q escapes %s (target %q)", linkRel, frame, target)
	}
	return nil
}
