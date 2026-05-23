package lane

import (
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
