package verify

import (
	"bytes"
	"testing"
)

func TestRFC6962TwoLeafRoot(t *testing.T) {
	l0 := []byte("leaf-zero")
	l1 := []byte("leaf-one")
	h0 := rfc6962LeafHash(l0)
	h1 := rfc6962LeafHash(l1)
	want := rfc6962NodeHash(h0, h1)

	got, err := rfc6962RootFromProof(h0, 0, 2, [][]byte{h1})
	if err != nil {
		t.Fatalf("index 0: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("index 0 root mismatch")
	}
	got, err = rfc6962RootFromProof(h1, 1, 2, [][]byte{h0})
	if err != nil {
		t.Fatalf("index 1: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("index 1 root mismatch")
	}
	// A truncated path must error, not silently accept.
	if _, err := rfc6962RootFromProof(h0, 0, 2, nil); err == nil {
		t.Error("expected error on truncated audit path")
	}
}
