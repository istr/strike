package lane

import "testing"

func TestMountsConflict(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"/a", "/a", true},
		{"/a", "/a/b", true},
		{"/a/b", "/a", true},
		{"/a/b", "/a/c", false},
		{"/a", "/abc", false},
		{"/a/b/c", "/a", true},
		{"/a/b/c", "/a/b", true},
		{"/", "/a", true},
		{"/a/", "/a", true}, // after Clean both are "/a"
	}
	for _, tt := range tests {
		if got := mountsConflict(ContainerPath(tt.a), ContainerPath(tt.b)); got != tt.want {
			t.Errorf("mountsConflict(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestIsPathPrefix(t *testing.T) {
	tests := []struct {
		prefix, full string
		want         bool
	}{
		{"/a", "/a/b", true},
		{"/a", "/a", false},   // identical, not strict prefix
		{"/a", "/abc", false}, // not a component boundary
		{"/", "/a", true},
		{"/a/b", "/a/b/c", true},
		{"/a/b", "/a/b/c/d", true},
		{"/a/b", "/a/bc", false},
	}
	for _, tt := range tests {
		if got := isPathPrefix(tt.prefix, tt.full); got != tt.want {
			t.Errorf("isPathPrefix(%q, %q) = %v, want %v", tt.prefix, tt.full, got, tt.want)
		}
	}
}
