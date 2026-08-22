package primitive

// String returns the host as a plain string. It is the single sanctioned
// Host-to-string conversion: call sites use h.String(), never string(h), so no
// type conversion sits in an argument list.
func (h Host) String() string {
	return string(h)
}
