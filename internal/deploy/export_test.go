package deploy

import (
	"context"

	"github.com/istr/strike/internal/lane"
)

// CaptureSnap exposes captureSnap for the external test package.
type CaptureSnap = captureSnap

// NewCaptureSnap creates a captureSnap for testing.
func NewCaptureSnap(name, image string, output []byte) CaptureSnap {
	return captureSnap{name: name, image: image, output: output}
}

// ProjectStatements exposes projectStatements for the external test package.
var ProjectStatements = projectStatements

// SignStatementKeyless exposes signStatementKeyless for the external test package.
var SignStatementKeyless = signStatementKeyless

// AssembleKeylessBundle exposes assembleKeylessBundle for the external test package.
var AssembleKeylessBundle = assembleKeylessBundle

// SetProduceBundles injects a bundle producer, replacing the real keyless
// chain in tests (the live test covers the real chain).
func SetProduceBundles(d *Deployer, f func(ctx context.Context, eps lane.KeylessEndpoints, statements [][]byte) ([][]byte, error)) {
	d.produceBundles = f
}
