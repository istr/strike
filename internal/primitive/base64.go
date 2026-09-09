package primitive

// String returns the base64 body as a plain string. It is the single
// sanctioned Base64-to-string conversion: call sites use b.String(), never
// string(b), so no type conversion sits in an argument list.
func (b Base64) String() string {
	return string(b)
}
