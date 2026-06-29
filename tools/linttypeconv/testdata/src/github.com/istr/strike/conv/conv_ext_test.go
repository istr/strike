package conv_test

import "github.com/istr/strike/conv"

func sink(string) {}

// extOwn converts conv.ID as a call argument from conv's OWN external test
// package (conv_test): not flagged, because the test package shares the type's
// ownership layer.
func extOwn(id conv.ID) {
	sink(string(id))
}
