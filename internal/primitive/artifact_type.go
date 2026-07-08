package primitive

// IsFile reports whether the artifact type is a single file rather than a
// directory. It owns the comparison against the generated file-type constant so
// the artifact-type vocabulary stays inside this package.
func (t FileArtifactType) IsFile() bool {
	return t == fileArtifactTypeFile
}
