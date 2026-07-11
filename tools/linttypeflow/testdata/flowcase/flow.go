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
