package primitive

// String returns the value as a plain string. It is the single sanctioned
// GitCommit-to-string conversion: call sites use c.String(), never
// string(c).
func (c GitCommit) String() string {
	return string(c)
}
