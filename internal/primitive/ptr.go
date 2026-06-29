package primitive

// Pointer constructors for the optional scalar fields CUE generates as `*T`
// from `field?: T @go(Name,optional=nillable)`. Each owns the string-to-type
// conversion in the type's own defining package, so a caller populates an
// optional field without converting at the call site. The value is not
// re-validated -- these match the raw conversion they replace; input crossing
// in from outside the schema-validated lane is validated at parse.

// ImageRefPtr returns a pointer to the ImageRef form of s.
func ImageRefPtr(s string) *ImageRef {
	v := ImageRef(s)
	return &v
}

// RelPathPtr returns a pointer to the RelPath form of s.
func RelPathPtr(s string) *RelPath {
	v := RelPath(s)
	return &v
}

// AbsPathPtr returns a pointer to the AbsPath form of s.
func AbsPathPtr(s string) *AbsPath {
	v := AbsPath(s)
	return &v
}

// IdentifierPtr returns a pointer to the Identifier form of s.
func IdentifierPtr(s string) *Identifier {
	v := Identifier(s)
	return &v
}

// DurationPtr returns a pointer to the Duration form of s.
func DurationPtr(s string) *Duration {
	v := Duration(s)
	return &v
}

// UserSpecPtr returns a pointer to the UserSpec form of s.
func UserSpecPtr(s string) *UserSpec {
	v := UserSpec(s)
	return &v
}
