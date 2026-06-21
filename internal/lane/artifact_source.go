package lane

import (
	"encoding/json"
	"fmt"
)

// ArtifactSource is the Go-side discriminated union for a deploy artifact
// reference (CUE #ArtifactSource, annotated @go(-) so the generator skips it).
// A deploy artifact references either a step's image (StepImageRef, by step) or
// a named file/directory output (OutputRef, by step+output). Parallel to
// DeployMethod and Peer.
type ArtifactSource interface {
	// SourceKind returns the discriminator: "image" or "output".
	SourceKind() string
}

// SourceKind implements ArtifactSource. A StepImageRef names a step image.
func (StepImageRef) SourceKind() string { return "image" }

// SourceKind implements ArtifactSource. An OutputRef names a file or directory
// output.
func (OutputRef) SourceKind() string { return "output" }

// UnmarshalJSON implements json.Unmarshaler for ArtifactRef. The from field is
// discriminated structurally: an OutputRef carries an "output" key, a
// StepImageRef does not. Mirrors DeploySpec.UnmarshalJSON.
func (r *ArtifactRef) UnmarshalJSON(data []byte) error {
	var aux struct {
		From json.RawMessage `json:"from"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.From) == 0 {
		return fmt.Errorf("artifact ref: from required")
	}
	var probe struct {
		Output *string `json:"output"`
	}
	if err := json.Unmarshal(aux.From, &probe); err != nil {
		return fmt.Errorf("artifact ref from: %w", err)
	}
	if probe.Output != nil {
		var o OutputRef
		if err := json.Unmarshal(aux.From, &o); err != nil {
			return fmt.Errorf("artifact ref output source: %w", err)
		}
		r.From = o
		return nil
	}
	var s StepImageRef
	if err := json.Unmarshal(aux.From, &s); err != nil {
		return fmt.Errorf("artifact ref image source: %w", err)
	}
	r.From = s
	return nil
}
