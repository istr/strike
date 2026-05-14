package registry

import "bytes"

// ExtractTarForTest is an exported wrapper around extractTar for use in tests.
func ExtractTarForTest(data []byte, dst string) error {
	return extractTar(bytes.NewReader(data), dst)
}
