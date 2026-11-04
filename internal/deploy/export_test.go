package deploy

import (
	"context"
	"testing"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/testutil"
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
// anchor is the fixture one: no test using this value dials the target.
func DeployRegistryForTest() lane.DeployRegistry {
	return lane.DeployRegistry{
		Type: "registry",
		Target: lane.DeployRegistryTarget{
			Type:       "https",
			Address:    endpoint.MustParseAuthority("registry.example.com:443"),
			Trust:      testutil.AnchorTrust(),
			Name:       "test/app",
			Credential: lane.RegistryCredential{Type: "bearer", Token: "registry-token"},
		},
	}
}

// FakeIDToken exposes fakeIDToken for the external test package.
var FakeIDToken = fakeIDToken

// RegistryTokenForTest delivers a registry token through REGISTRY_ID_TOKEN,
// for tests whose deploy reaches the push, and returns the lane.secrets entry
// that declares it under the name every test target's credential uses. The
// token is unsigned, because nothing in strike verifies it; it lives within
// the bound, and its audience is a registry's, not the oidc audience.
func RegistryTokenForTest(t *testing.T) map[primitive.Identifier]lane.SecretSource {
	t.Helper()
	t.Setenv("REGISTRY_ID_TOKEN", fakeIDToken(`{"aud":"https://registry.example.com","iat":1000,"exp":1600}`))
	return map[primitive.Identifier]lane.SecretSource{DeployRegistryForTest().Target.Credential.Token: "env://REGISTRY_ID_TOKEN"}
}
