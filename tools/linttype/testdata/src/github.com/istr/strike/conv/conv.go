package conv

// ID is a strike named string type whose conversions are owned in this
// package, the one place its behavior lives.
type ID string

func sink(string) {}

// inOwn converts ID as a call argument inside its own package: not flagged,
// because the type's defining package owns the boundary.
func inOwn(id ID) {
	sink(string(id))
}
