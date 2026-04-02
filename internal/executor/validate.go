package executor

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/istr/strike/internal/lane"
)

// ValidateOutput checks that an extracted output matches its expected properties.
func ValidateOutput(path string, info fs.FileInfo, expected *lane.OutputValidation) error {
	// Size bounds
	if expected.MinSize > 0 && info.Size() < expected.MinSize {
		return fmt.Errorf("size %d below minimum %d", info.Size(), expected.MinSize)
	}
	if expected.MaxSize > 0 && info.Size() > expected.MaxSize {
		return fmt.Errorf("size %d exceeds maximum %d", info.Size(), expected.MaxSize)
	}

	// Content type validation
	if expected.ContentType != "" {
		if err := ValidateContentType(path, expected.ContentType); err != nil {
			return err
		}
	}

	return nil
}

// ValidateContentType checks magic bytes against the declared content type.
func ValidateContentType(path string, contentType string) (err error) {
	f, err := os.Open(path) //nolint:gosec // G304: output file path from step execution
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	header := make([]byte, 20)
	n, err := f.Read(header)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read header: %w", err)
	}
	header = header[:n]

	switch contentType {
	case "executable/elf-amd64":
		return ValidateELFAmd64(header)
	case "application/tar+gzip":
		return ValidateGzip(header)
	default:
		// Unknown content type -- no validation
		return nil
	}
}

// ValidateELFAmd64 checks ELF magic bytes and x86-64 architecture.
func ValidateELFAmd64(header []byte) error {
	if len(header) < 20 {
		return fmt.Errorf("file too small for ELF header")
	}
	// ELF magic: 0x7f 'E' 'L' 'F'
	if header[0] != 0x7f || header[1] != 'E' || header[2] != 'L' || header[3] != 'F' {
		return fmt.Errorf("not an ELF binary (magic: %x)", header[:4])
	}
	// EI_CLASS: 2 = 64-bit
	if header[4] != 2 {
		return fmt.Errorf("not a 64-bit ELF (class: %d)", header[4])
	}
	// e_machine at offset 18: 0x3E = EM_X86_64 (little-endian)
	machine := uint16(header[18]) | uint16(header[19])<<8
	if machine != 0x3E {
		return fmt.Errorf("not x86-64 (machine: 0x%x)", machine)
	}
	return nil
}

// ValidateGzip checks gzip magic bytes.
func ValidateGzip(header []byte) error {
	if len(header) < 2 {
		return fmt.Errorf("file too small for gzip header")
	}
	if header[0] != 0x1f || header[1] != 0x8b {
		return fmt.Errorf("not gzip (magic: %x)", header[:2])
	}
	return nil
}
