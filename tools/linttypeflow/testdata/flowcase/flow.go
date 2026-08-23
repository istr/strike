// Package flowcase is a linttypeflow test fixture. It exercises the two gating
// flow classes so the detectors and the gate can be checked end to end.
package flowcase

// Digest is a strike-style scalar named type.
type Digest string

// roundtripLocal detypes the value to a local plain string and retypes it,
// which is the roundtrip-local class.
func roundtripLocal(d Digest) Digest {
	s := string(d)
	return Digest(s)
}

// resultStringScalar returns a typed value as a plain string, which is the
// result-string-scalar class.
func resultStringScalar(d Digest) string {
	return string(d)
}

// clean keeps the value typed end to end and yields no covered finding.
func clean(d Digest) Digest {
	return d
}

// String is the sanctioned Digest-to-string boundary: it detypes its own
// receiver, so the survey records the fact as a boundary and the gate drops it.
func (d Digest) String() string {
	return string(d)
}

// Hex detypes the receiver inside one of its own type's methods, which the
// type owns and the gate therefore allows.
func (d Digest) Hex() string {
	return string(d)[7:]
}

// Wrapper renders a Digest it does not own.
type Wrapper struct{ d Digest }

// String has the boundary shape but detypes a foreign value rather than its
// own receiver, so it stays gated.
func (w Wrapper) String() string {
	return string(w.d)
}

// String is a package-level helper, not a method, so it stays gated too.
func String(d Digest) string {
	return string(d)
}

// bypassStringer detypes a Digest at a call site instead of calling
// d.String(), which is the detype-bypasses-stringer class.
func bypassStringer(d Digest) int {
	return len(string(d))
}
