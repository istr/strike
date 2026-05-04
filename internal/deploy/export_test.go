package deploy

import (
	"context"

	"github.com/istr/strike/internal/lane"
)

// PAEEncode exposes paeEncode for the external test package.
var PAEEncode = paeEncode

// ExecuteMethod exposes executeMethod for the external test package.
func (d *Deployer) ExecuteMethod(ctx context.Context, spec lane.DeploySpec, peers []lane.Peer) error {
	return d.executeMethod(ctx, spec, peers)
}

// CaptureSnap exposes captureSnap for the external test package.
type CaptureSnap = captureSnap

// NewCaptureSnap creates a captureSnap for testing.
func NewCaptureSnap(name, image string, output []byte) CaptureSnap {
	return captureSnap{name: name, image: image, output: output}
}
