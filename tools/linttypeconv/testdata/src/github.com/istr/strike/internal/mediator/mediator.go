package mediator

import "github.com/istr/strike/conv"

func canonicalize(string) {}

// useAllow converts a foreign named type as a call argument, but the
// (package, callee) pair is on the central allowlist: not flagged.
func useAllow(id conv.ID) {
	canonicalize(string(id))
}
