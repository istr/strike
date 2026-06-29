package primitive

// NewImageRef returns the ImageRef form of s. It does not validate -- callers
// constructing a reference from already-trusted parts (a digest computed in
// process, a test input) use it to own the conversion in this package; a
// reference crossing in from outside the schema-validated lane is validated at
// parse.
func NewImageRef(s string) ImageRef {
	return ImageRef(s)
}
