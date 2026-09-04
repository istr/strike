package primitive

import "strconv"

// String returns the port as its decimal wire form. It is the single
// sanctioned Port-to-string projection, mirroring Host.String: call sites use
// p.String() rather than converting the value and formatting it themselves, so
// the decimal grammar is owned by the defining package and no type conversion
// sits in an argument list.
func (p Port) String() string {
	return strconv.Itoa(int(p))
}
