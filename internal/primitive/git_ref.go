package primitive

// String returns the value as a plain string. It is the single sanctioned
// GitRef-to-string conversion: call sites use r.String(), never
// string(r).
func (r GitRef) String() string {
	return string(r)
}
