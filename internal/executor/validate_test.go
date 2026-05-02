package executor_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
)

func TestValidateELFAmd64(t *testing.T) {
	// Minimal valid ELF x86-64 header
	header := make([]byte, 20)
	header[0] = 0x7f
	header[1] = 'E'
	header[2] = 'L'
	header[3] = 'F'
	header[4] = 2     // 64-bit
	header[18] = 0x3E // EM_X86_64 low byte
	header[19] = 0x00 // EM_X86_64 high byte

	if err := executor.ValidateELFAmd64(header); err != nil {
		t.Fatalf("valid ELF header rejected: %v", err)
	}
}

func TestValidateELFAmd64_NotELF(t *testing.T) {
	header := []byte("#!/bin/bash\necho hi")
	if err := executor.ValidateELFAmd64(header); err == nil {
		t.Fatal("expected error for non-ELF")
	}
}

func TestValidateELFAmd64_WrongArch(t *testing.T) {
	header := make([]byte, 20)
	header[0] = 0x7f
	header[1] = 'E'
	header[2] = 'L'
	header[3] = 'F'
	header[4] = 2     // 64-bit
	header[18] = 0xB7 // aarch64
	header[19] = 0x00

	if err := executor.ValidateELFAmd64(header); err == nil {
		t.Fatal("expected error for aarch64")
	}
}

func TestValidateGzip(t *testing.T) {
	header := []byte{0x1f, 0x8b, 0x08} // gzip magic + deflate method
	if err := executor.ValidateGzip(header); err != nil {
		t.Fatalf("valid gzip rejected: %v", err)
	}
}

func TestValidateGzip_NotGzip(t *testing.T) {
	header := []byte{0x50, 0x4b} // zip magic
	if err := executor.ValidateGzip(header); err == nil {
		t.Fatal("expected error for non-gzip")
	}
}

func TestValidateOutput_SizeBounds(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.bin")
	if err := os.WriteFile(path, make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// Within bounds
	err = executor.ValidateOutput(path, info, &lane.OutputValidation{MinSize: 50, MaxSize: 200})
	if err != nil {
		t.Fatalf("within bounds rejected: %v", err)
	}

	// Below minimum
	err = executor.ValidateOutput(path, info, &lane.OutputValidation{MinSize: 200})
	if err == nil {
		t.Fatal("expected error for below minimum")
	}

	// Above maximum
	err = executor.ValidateOutput(path, info, &lane.OutputValidation{MaxSize: 50})
	if err == nil {
		t.Fatal("expected error for above maximum")
	}
}

func TestValidateContentType_ELF(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "binary")

	// Write a minimal ELF header
	header := make([]byte, 64)
	header[0] = 0x7f
	header[1] = 'E'
	header[2] = 'L'
	header[3] = 'F'
	header[4] = 2     // 64-bit
	header[18] = 0x3E // x86-64
	if err := os.WriteFile(path, header, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := executor.ValidateContentType(path, "executable/elf-amd64"); err != nil {
		t.Fatalf("valid ELF rejected: %v", err)
	}
}

func TestValidateContentType_InvalidELF(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "script.sh")
	if err := os.WriteFile(path, []byte("#!/bin/bash\necho hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := executor.ValidateContentType(path, "executable/elf-amd64"); err == nil {
		t.Fatal("expected error for shell script validated as ELF")
	}
}

func TestNetworkMode(t *testing.T) {
	tests := []struct {
		name  string
		want  string
		peers []lane.Peer
	}{
		{"empty", "none", nil},
		{"empty slice", "none", []lane.Peer{}},
		{"one oci peer", "bridge", []lane.Peer{{"type": "oci", "registry": "localhost:5555"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := executor.NetworkMode(tt.peers)
			if got != tt.want {
				t.Errorf("NetworkMode(%v) = %q, want %q", tt.peers, got, tt.want)
			}
		})
	}
}
