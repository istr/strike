package lane

import (
	"path"

	"github.com/istr/strike/internal/primitive"
)

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
	return string(out.ID)
}

// Output returns the declared FileOutput named out on the step named step, or
// nil if the step or the output does not exist. It resolves a producer
// reference ({step, output}) to the referenced output declaration; callers that
// have passed ValidateLane can rely on a non-nil result for a declared input,
// pack file, or deploy artifact.
func (l *Lane) Output(step, out primitive.Identifier) *FileOutput {
	s := l.step(step)
	if s == nil {
		return nil
	}
	return findOutput(s, out)
}
