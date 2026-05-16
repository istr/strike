package lane

// Ptr returns a pointer to v. Convenience for constructing
// struct literals with optional pointer fields generated from
// CUE optional definitions (`field?: T @go(Name,optional=nillable)`).
// The companion to nil-checks on the read side.
func Ptr[T any](v T) *T { return &v }
