package executor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/lane"
)

func TestValidateELFAmd64(t *testing.T) {
	// Minimal valid ELF x86-64 header
	header := make([]byte, 20)
	header[0] = 0x7f
	header[1] = 'E'
	header[2] = 'L'
	header[3] = 'F'
	header[4] = 2    // 64-bit
	header[18] = 0x3E // EM_X86_64 low byte
	header[19] = 0x00 // EM_X86_64 high byte

	if err := validateELFAmd64(header); err != nil {
		t.Fatalf("valid ELF header rejected: %v", err)
	}
}

func TestValidateELFAmd64_NotELF(t *testing.T) {
	header := []byte("#!/bin/bash\necho hi")
	if err := validateELFAmd64(header); err == nil {
		t.Fatal("expected error for non-ELF")
	}
}

func TestValidateELFAmd64_WrongArch(t *testing.T) {
	header := make([]byte, 20)
	header[0] = 0x7f
	header[1] = 'E'
	header[2] = 'L'
	header[3] = 'F'
	header[4] = 2    // 64-bit
	header[18] = 0xB7 // aarch64
	header[19] = 0x00

	if err := validateELFAmd64(header); err == nil {
		t.Fatal("expected error for aarch64")
	}
}

func TestValidateGzip(t *testing.T) {
	header := []byte{0x1f, 0x8b, 0x08} // gzip magic + deflate method
	if err := validateGzip(header); err != nil {
		t.Fatalf("valid gzip rejected: %v", err)
	}
}

func TestValidateGzip_NotGzip(t *testing.T) {
	header := []byte{0x50, 0x4b} // zip magic
	if err := validateGzip(header); err == nil {
		t.Fatal("expected error for non-gzip")
	}
}

func TestValidateOutput_SizeBounds(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.bin")
	os.WriteFile(path, make([]byte, 100), 0o644)
	info, _ := os.Stat(path)

	// Within bounds
	err := validateOutput(path, info, &lane.OutputValidation{MinSize: 50, MaxSize: 200})
	if err != nil {
		t.Fatalf("within bounds rejected: %v", err)
	}

	// Below minimum
	err = validateOutput(path, info, &lane.OutputValidation{MinSize: 200})
	if err == nil {
		t.Fatal("expected error for below minimum")
	}

	// Above maximum
	err = validateOutput(path, info, &lane.OutputValidation{MaxSize: 50})
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
	header[4] = 2    // 64-bit
	header[18] = 0x3E // x86-64
	os.WriteFile(path, header, 0o755)

	if err := validateContentType(path, "executable/elf-amd64"); err != nil {
		t.Fatalf("valid ELF rejected: %v", err)
	}
}

func TestValidateContentType_InvalidELF(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "script.sh")
	os.WriteFile(path, []byte("#!/bin/bash\necho hello"), 0o755)

	if err := validateContentType(path, "executable/elf-amd64"); err == nil {
		t.Fatal("expected error for shell script validated as ELF")
	}
}

func TestHashOutput(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "data.bin")
	os.WriteFile(path, []byte("deterministic content"), 0o644)

	d1, err := hashOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := hashOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("hash not deterministic: %q vs %q", d1, d2)
	}
}

func TestBaseFlagsPresent(t *testing.T) {
	// Verify the hardened profile flags are present
	expected := map[string]bool{
		"--cap-drop=ALL":                   false,
		"--read-only":                      false,
		"--rm":                             false,
		"--security-opt=no-new-privileges": false,
	}
	for _, f := range baseFlags {
		if _, ok := expected[f]; ok {
			expected[f] = true
		}
	}
	for flag, found := range expected {
		if !found {
			t.Errorf("missing base flag: %s", flag)
		}
	}
}

func TestNetworkFlag(t *testing.T) {
	disabled := networkFlag(false)
	if len(disabled) != 1 || disabled[0] != "--network=none" {
		t.Errorf("network disabled: %v", disabled)
	}

	enabled := networkFlag(true)
	if len(enabled) != 0 {
		t.Errorf("network enabled should return nil, got: %v", enabled)
	}
}

func TestOutputMount(t *testing.T) {
	m := outputMount("/tmp/abc123")
	if len(m) != 2 || m[0] != "-v" || m[1] != "/tmp/abc123:/out:rw,noexec,nosuid" {
		t.Errorf("unexpected output mount: %v", m)
	}
}
