package use

import "github.com/istr/strike/conv"

type box struct{ Name string }

func f(string) {}

// direct converts the foreign named type straight into a call argument: the
// one flagged shape.
func direct(id conv.ID) {
	f(string(id)) // want `conversion of ID in a call argument`
}

// assigned hoists the conversion to a named local first: not a call argument.
func assigned(id conv.ID) {
	s := string(id)
	f(s)
}

// lit converts into a composite-literal field: not a call argument.
func lit(id conv.ID) box {
	return box{Name: string(id)}
}

// ret converts in a bare return: not a call argument.
func ret(id conv.ID) string {
	return string(id)
}

// raw is a builtin string([]byte) conversion with no strike type involved.
func raw(b []byte) {
	f(string(b))
}
