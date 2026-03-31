package executor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/istr/strike/lane"
)

// Executor runs step containers with the hardened security profile
// and manages artifact extraction and validation.
type Executor struct {
	LaneRoot string
}

// RunStep executes a single step: resolve inputs, run container, extract
// and validate outputs, register in state.
func (e *Executor) RunStep(ctx context.Context, step *lane.Step, state *lane.State) error {
	outDir, err := os.MkdirTemp("", "strike-out-"+step.Name+"-")
	if err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(outDir)
		}
	}()

	started := time.Now()

	// Build podman run arguments using the hardened security profile
	args := []string{"run"}
	args = append(args, baseFlags...)
	args = append(args, networkFlag(step.Network)...)
	args = append(args, outputMount(outDir)...)

	// Mount inputs (read-only)
	for _, inp := range step.Inputs {
		a, resolveErr := state.Resolve(inp.From)
		if resolveErr != nil {
			return fmt.Errorf("step %q: resolve input %q: %w", step.Name, inp.Name, resolveErr)
		}
		args = append(args, inputMount(a.LocalPath, inp.Mount)...)
	}

	// Mount sources (read-only)
	for _, src := range step.Sources {
		path := src.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(e.LaneRoot, path)
		}
		args = append(args, inputMount(path, src.Mount)...)
	}

	// Environment variables
	envKeys := make([]string, 0, len(step.Env))
	for k := range step.Env {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)
	for _, k := range envKeys {
		args = append(args, "--env", k+"="+step.Env[k])
	}

	// Image
	args = append(args, step.Image)

	// Command (exec form)
	args = append(args, step.Args...)

	// Execute
	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	exitCode := 0
	if runErr := cmd.Run(); runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		return fmt.Errorf("step %q: container exited with code %d: %w", step.Name, exitCode, runErr)
	}

	// Extract and validate declared outputs
	result := lane.StepResult{
		Name:      step.Name,
		StepType:  "run",
		StartedAt: started,
		Duration:  time.Since(started),
		Inputs:    make(map[string]string),
		Outputs:   make(map[string]string),
		ExitCode:  exitCode,
	}

	for _, out := range step.Outputs {
		if out.Type == "image" {
			continue // image outputs handled separately
		}

		hostPath := filepath.Join(outDir, filepath.Base(out.Path))
		if _, statErr := os.Stat(hostPath); statErr != nil {
			return fmt.Errorf("step %q: declared output %q not found at %s", step.Name, out.Name, hostPath)
		}

		// Compute digest
		digest, hashErr := hashOutput(hostPath)
		if hashErr != nil {
			return fmt.Errorf("step %q: hash output %q: %w", step.Name, out.Name, hashErr)
		}

		// Get size
		info, _ := os.Stat(hostPath)
		size := info.Size()

		// Validate expected properties
		if out.Expected != nil {
			if valErr := validateOutput(hostPath, info, out.Expected); valErr != nil {
				return fmt.Errorf("step %q: output %q validation failed: %w", step.Name, out.Name, valErr)
			}
		}

		// Register in state
		a := lane.Artifact{
			Type:      out.Type,
			Digest:    digest,
			Size:      size,
			LocalPath: hostPath,
		}
		if out.Expected != nil && out.Expected.ContentType != "" {
			a.ContentType = out.Expected.ContentType
		}
		if regErr := state.Register(step.Name, out.Name, a); regErr != nil {
			return fmt.Errorf("step %q: register output %q: %w", step.Name, out.Name, regErr)
		}
		result.Outputs[out.Name] = digest
	}

	state.RecordStep(result)
	return nil
}

// hashOutput computes sha256 of a file or directory.
func hashOutput(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return hashDir(path)
	}
	return hashFile(path)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func hashDir(dir string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		h.Write([]byte(rel))
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		// Include size for determinism without reading all bytes twice
		sizeBuf := make([]byte, 8)
		binary.LittleEndian.PutUint64(sizeBuf, uint64(info.Size()))
		h.Write(sizeBuf)
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		h.Write(content)
		return nil
	})
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// validateOutput checks that an extracted output matches its expected properties.
func validateOutput(path string, info fs.FileInfo, expected *lane.OutputValidation) error {
	// Size bounds
	if expected.MinSize > 0 && info.Size() < expected.MinSize {
		return fmt.Errorf("size %d below minimum %d", info.Size(), expected.MinSize)
	}
	if expected.MaxSize > 0 && info.Size() > expected.MaxSize {
		return fmt.Errorf("size %d exceeds maximum %d", info.Size(), expected.MaxSize)
	}

	// Content type validation
	if expected.ContentType != "" {
		if err := validateContentType(path, expected.ContentType); err != nil {
			return err
		}
	}

	return nil
}

// validateContentType checks magic bytes against the declared content type.
func validateContentType(path string, contentType string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	header := make([]byte, 20)
	n, err := f.Read(header)
	if err != nil && err != io.EOF {
		return fmt.Errorf("read header: %w", err)
	}
	header = header[:n]

	switch contentType {
	case "executable/elf-amd64":
		return validateELFAmd64(header)
	case "application/tar+gzip":
		return validateGzip(header)
	default:
		// Unknown content type — no validation
		return nil
	}
}

// validateELFAmd64 checks ELF magic bytes and x86-64 architecture.
func validateELFAmd64(header []byte) error {
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

// validateGzip checks gzip magic bytes.
func validateGzip(header []byte) error {
	if len(header) < 2 {
		return fmt.Errorf("file too small for gzip header")
	}
	if header[0] != 0x1f || header[1] != 0x8b {
		return fmt.Errorf("not gzip (magic: %x)", header[:2])
	}
	return nil
}
