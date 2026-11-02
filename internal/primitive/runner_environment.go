package primitive

// String returns the value as a plain string. It is the single sanctioned
// RunnerEnvironment-to-string conversion: call sites use e.String(), never
// string(e).
func (e RunnerEnvironment) String() string {
	return string(e)
}
