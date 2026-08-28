package deploy

import (
	"context"
	"strings"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
)

// CaptureSnap exposes captureSnap for the external test package.
type CaptureSnap = captureSnap

// NewCaptureSnap creates a captureSnap for testing.
func NewCaptureSnap(name, image string, output []byte) CaptureSnap {
	return captureSnap{name: name, image: image, output: output}
}

// SignStatementKeyless exposes signStatementKeyless for the external test package.
var SignStatementKeyless = signStatementKeyless

// AssembleKeylessBundle exposes assembleKeylessBundle for the external test package.
var AssembleKeylessBundle = assembleKeylessBundle

// SetProduceBundles injects a bundle producer, replacing the real keyless
// chain in tests (the live test covers the real chain).
func SetProduceBundles(d *Deployer, f func(ctx context.Context, eps lane.KeylessEndpoints, statements [][]byte) ([][]byte, error)) {
	d.produceBundles = f
}

// DeployRegistryForTest returns a registry deploy method with a syntactically
// valid push target, for tests whose subject is not the push itself. The
// fingerprint is a placeholder: no test using this value dials the target.
func DeployRegistryForTest() lane.DeployRegistry {
	return lane.DeployRegistry{
		Type: "registry",
		Target: lane.DeployRegistryTarget{
			Type:    "https",
			Address: endpoint.MustParseAuthority("registry.example.com:443"),
			Trust: endpoint.Fingerprint{
				Type:        "certFingerprint",
				Fingerprint: primitive.DigestFromHex(strings.Repeat("e", 64)),
			},
			Name: "test/app",
		},
	}
}
