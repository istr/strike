package lane

import (
	"iter"

	"github.com/istr/strike/internal/primitive"
)

// Inputs yields the input references declared by the step named id, in
// declaration order. Each InputRef carries its producer reference (From),
// mount, and optional subpath. An unknown id yields nothing.
func (l *Lane) Inputs(id primitive.Identifier) iter.Seq[InputRef] {
	return func(yield func(InputRef) bool) {
		s := l.step(id)
		if s == nil {
			return
		}
		for _, in := range s.Inputs {
			if !yield(in) {
				return
			}
		}
	}
}

// PackFiles yields the pack-file references declared by the step named id,
// in declaration order. A step with no pack spec yields nothing.
func (l *Lane) PackFiles(id primitive.Identifier) iter.Seq[PackFile] {
	return func(yield func(PackFile) bool) {
		s := l.step(id)
		if s == nil || s.Pack == nil {
			return
		}
		for _, f := range s.Pack.Files {
			if !yield(f) {
				return
			}
		}
	}
}

// DeployArtifacts yields the deploy artifact references declared by the step
// named id, keyed by artifact name. A step with no deploy spec yields nothing.
// The artifact map has no inherent order; a caller that needs a deterministic
// sequence sorts by the yielded name.
func (l *Lane) DeployArtifacts(id primitive.Identifier) iter.Seq2[primitive.Identifier, ArtifactRef] {
	return func(yield func(primitive.Identifier, ArtifactRef) bool) {
		s := l.step(id)
		if s == nil || s.Deploy == nil {
			return
		}
		for name, ref := range s.Deploy.Artifacts {
			artName := primitive.Identifier(name)
			if !yield(artName, ref) {
				return
			}
		}
	}
}

// step returns a pointer to the lane step named id, or nil if no such step
// exists. The pointer aliases into l.Steps, so callers must not mutate the
// lane while iterating.
func (l *Lane) step(id primitive.Identifier) *Step {
	for i := range l.Steps {
		if l.Steps[i].ID == id {
			return &l.Steps[i]
		}
	}
	return nil
}
