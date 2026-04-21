package lane_test

import (
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

func TestValidateProvenance_Git_Valid(t *testing.T) {
	raw := []byte(`{
		"type": "git",
		"uri": "https://github.com/foo/bar.git",
		"commit": "0123456789abcdef0123456789abcdef01234567",
		"ref": "refs/heads/main",
		"signature": {"method": "gpg", "verified": true, "signer": "alice@example.com", "fingerprint": "ABCD1234"},
		"fetched_at": "2026-04-21T10:00:00Z"
	}`)
	rec, err := lane.ValidateProvenance("git", raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Type != "git" {
		t.Errorf("type = %q, want git", rec.Type)
	}
	if !rec.IsSigned() {
		t.Error("expected IsSigned() == true")
	}
}

func TestValidateProvenance_Git_Minimal(t *testing.T) {
	raw := []byte(`{
		"type": "git",
		"uri": "https://github.com/foo/bar.git",
		"commit": "0123456789abcdef0123456789abcdef01234567"
	}`)
	rec, err := lane.ValidateProvenance("git", raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.IsSigned() {
		t.Error("expected IsSigned() == false for record without signature")
	}
}

func TestValidateProvenance_Tarball_Valid(t *testing.T) {
	raw := []byte(`{
		"type": "tarball",
		"uri": "https://example.com/src.tar.gz",
		"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}`)
	rec, err := lane.ValidateProvenance("tarball", raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Type != "tarball" {
		t.Errorf("type = %q, want tarball", rec.Type)
	}
}

func TestValidateProvenance_OCI_Valid(t *testing.T) {
	raw := []byte(`{
		"type": "oci",
		"uri": "ghcr.io/foo/bar",
		"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}`)
	rec, err := lane.ValidateProvenance("oci", raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Type != "oci" {
		t.Errorf("type = %q, want oci", rec.Type)
	}
}

func TestValidateProvenance_URL_Valid(t *testing.T) {
	raw := []byte(`{
		"type": "url",
		"uri": "https://example.com/file.bin",
		"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}`)
	rec, err := lane.ValidateProvenance("url", raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Type != "url" {
		t.Errorf("type = %q, want url", rec.Type)
	}
}

func TestValidateProvenance_TypeMismatch(t *testing.T) {
	raw := []byte(`{
		"type": "tarball",
		"uri": "https://example.com/src.tar.gz",
		"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}`)
	_, err := lane.ValidateProvenance("git", raw)
	if err == nil {
		t.Fatal("expected error on type mismatch")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should mention mismatch: %v", err)
	}
}

func TestValidateProvenance_InvalidCommit(t *testing.T) {
	raw := []byte(`{"type": "git", "uri": "x", "commit": "not-a-sha"}`)
	_, err := lane.ValidateProvenance("git", raw)
	if err == nil {
		t.Fatal("expected schema validation error")
	}
}

func TestValidateProvenance_UnknownType(t *testing.T) {
	_, err := lane.ValidateProvenance("svn", []byte(`{}`))
	if err == nil {
		t.Fatal("expected error on unknown type")
	}
	if !strings.Contains(err.Error(), "unknown provenance type") {
		t.Errorf("error should mention unknown type: %v", err)
	}
}

func TestValidateProvenance_InvalidJSON(t *testing.T) {
	_, err := lane.ValidateProvenance("git", []byte(`{not json`))
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestValidateProvenance_SignedFalse(t *testing.T) {
	raw := []byte(`{
		"type": "git",
		"uri": "https://github.com/foo/bar.git",
		"commit": "0123456789abcdef0123456789abcdef01234567",
		"signature": {"method": "gpg", "verified": false, "signer": "alice@example.com"}
	}`)
	rec, err := lane.ValidateProvenance("git", raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.IsSigned() {
		t.Error("expected IsSigned() == false when verified=false")
	}
}
