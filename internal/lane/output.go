package lane

import "path"

// OutputContentPrefix returns the top-level name under which an output's content
// is rooted inside its wrapped OCI layer: the base name of the output path
// when a subpath is declared, or the output name when the output is the
// whole workdir (path absent). wrapOutputs uses it as the layer destination
// prefix; input resolution uses it to find the content root in an extracted
// producer artifact.
func OutputContentPrefix(out FileOutput) string {
	if out.Path != nil {
		return path.Base(out.Path.String())
	}
	return out.ID
}
