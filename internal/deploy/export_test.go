package deploy

// CaptureSnap exposes captureSnap for the external test package.
type CaptureSnap = captureSnap

// NewCaptureSnap creates a captureSnap for testing.
func NewCaptureSnap(name, image string, output []byte) CaptureSnap {
	return captureSnap{name: name, image: image, output: output}
}
