package deploy

// CaptureSnap exposes captureSnap for the external test package.
type CaptureSnap = captureSnap

// NewCaptureSnap creates a captureSnap for testing.
func NewCaptureSnap(name, image string, output []byte) CaptureSnap {
	return captureSnap{name: name, image: image, output: output}
}

// DeploySchema exposes deploySchema for the external test package.
var DeploySchema = deploySchema

// ProjectStatements exposes projectStatements for the external test package.
var ProjectStatements = projectStatements

// SignStatementKeyless exposes signStatementKeyless for the external test package.
var SignStatementKeyless = signStatementKeyless

// AssembleKeylessBundle exposes assembleKeylessBundle for the external test package.
var AssembleKeylessBundle = assembleKeylessBundle
