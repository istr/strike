package allowed

import "github.com/istr/strike/conv"

func sink(string) {}

// onAllowlist converts a foreign named type as a call argument, but the
// (package, callee) pair is on the allowlist the test installs: not flagged.
func onAllowlist(id conv.ID) {
	sink(string(id))
}
