package contract

// Schema code generation: JSON Schema exports, gengotypes type generation, and
// the enum-constant recovery pass. Run via `go generate ./contract`.

//go:generate go tool cue export ./lane -e "#Lane" --out jsonschema --force -o lane.schema.json
//go:generate go tool cue export ./attest -e "#Attestation" --out jsonschema --force -o attestation.schema.json
//go:generate go tool cue export ./trustlayers --out json --force -o trust-layers.json
//go:generate go tool cue exp gengotypes ./lane
//go:generate go tool cue exp gengotypes ./primitive
//go:generate go tool cue exp gengotypes ./endpoint
//go:generate go tool cue exp gengotypes ./output
//go:generate go tool cue exp gengotypes ./provenance
//go:generate go tool cue exp gengotypes ./record
//go:generate go tool cue exp gengotypes ./attest
//go:generate go run github.com/istr/strike/tools/genenums lane primitive endpoint output provenance record attest
