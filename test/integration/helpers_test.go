package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
)

// Digest-pinned image references matching lane.yaml.
const (
	goImage    = "cgr.dev/chainguard/go@sha256:4ec098b553c8d74d9f01925578660b2bfcdee4ef45e5ab082250cf9675a0e28b"
	staticBase = "cgr.dev/chainguard/static@sha256:2fdfacc8d61164aa9e20909dceec7cc28b9feb66580e8e1a65b9f2443c53b61b"
)

// needsEngine returns a live container.Engine or skips the test.
//
// By default, the helper probes the local podman socket via container.New().
// Set STRIKE_INTEGRATION=0 to skip integration tests unconditionally.
func needsEngine(t *testing.T) container.Engine {
	t.Helper()
	if os.Getenv("STRIKE_INTEGRATION") == "0" {
		t.Skip("integration tests disabled (STRIKE_INTEGRATION=0)")
	}
	engine, err := container.New()
	if err != nil {
		t.Skipf("no container engine: %v", err)
	}
	ctx := context.Background()
	if err := engine.Ping(ctx); err != nil {
		t.Skipf("container engine not responding: %v", err)
	}
	return engine
}

// ensureImage pulls an image if it is not already in the local store.
func ensureImage(t *testing.T, engine container.Engine, ref string) {
	t.Helper()
	ctx := context.Background()
	exists, err := engine.ImageExists(ctx, ref)
	if err != nil {
		t.Fatalf("image exists check: %v", err)
	}
	if exists {
		return
	}
	t.Logf("pulling %s ...", ref)
	if pullErr := engine.ImagePull(ctx, ref); pullErr != nil {
		t.Fatalf("image pull %s: %v", ref, pullErr)
	}
}

// generateTestKey creates a fresh ECDSA P-256 key pair and returns the
// private key PEM. Each test run gets a unique key.
func generateTestKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal test key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// buildTestBinary compiles the test Go program in a container and returns
// the path to the resulting binary.
func buildTestBinary(t *testing.T, engine container.Engine) string {
	t.Helper()
	srcDir, absErr := filepath.Abs(filepath.Join("testdata", "src"))
	if absErr != nil {
		t.Fatalf("abs path: %v", absErr)
	}
	outDir := t.TempDir()
	ctx := context.Background()

	var stdout, stderr bytes.Buffer
	exitCode, err := engine.ContainerRun(ctx, container.RunOpts{
		Image: goImage,
		Cmd: []string{
			"build", "-C", "/src", "-trimpath",
			"-buildvcs=false", "-ldflags=-s -w",
			"-o", "/out/app", ".",
		},
		Env:    map[string]string{"CGO_ENABLED": "0", "GOCACHE": "/tmp/gocache", "GOPATH": "/tmp/gopath"},
		Stdout: &stdout,
		Stderr: &stderr,
		Mounts: []container.Mount{
			{Source: srcDir, Target: "/src", ReadOnly: true},
			{Source: outDir, Target: "/out"},
		},
		CapDrop:  []string{"ALL"},
		ReadOnly: true,
		Tmpfs:    map[string]string{"/tmp": "rw,noexec,nosuid,size=512m"},
		Remove:   true,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("build: exit code %d\nstdout: %s\nstderr: %s",
			exitCode, stdout.String(), stderr.String())
	}

	binPath := filepath.Join(outDir, "app")
	info, statErr := os.Stat(binPath)
	if statErr != nil {
		t.Fatalf("binary not found: %v", statErr)
	}
	t.Logf("binary: %s (%d bytes)", binPath, info.Size())
	return binPath
}

// packTestImage assembles an OCI image from a binary and returns
// the pack result and the root-scoped output directory.
func packTestImage(t *testing.T, binPath string, keyPEM []byte) (*executor.PackResult, *os.Root, string) {
	t.Helper()
	outDir := t.TempDir()
	outRoot, err := os.OpenRoot(outDir)
	if err != nil {
		t.Fatal(err)
	}

	result, packErr := executor.Pack(context.Background(), executor.PackOpts{
		Spec: &lane.PackSpec{
			Base: lane.ImageRef(staticBase),
			Files: []lane.PackFile{
				{From: "build.app", Dest: "/app", Mode: 0o755},
			},
			Config: &lane.ImageConfig{
				Entrypoint: []string{"/app"},
				User:       "65534:65534",
			},
		},
		InputPaths:  map[string]string{"build.app": binPath},
		OutputRoot:  outRoot,
		OutputName:  "image.tar",
		SigningKey:  keyPEM,
		KeyPassword: nil,
	})
	if packErr != nil {
		outRoot.Close() //nolint:errcheck,gosec // os.Root.Close on error path; test will fatalf next
		t.Fatalf("pack: %v", packErr)
	}
	return result, outRoot, outDir
}

// testPublicKeyFrom derives the ECDSA public key from a private key PEM.
func testPublicKeyFrom(t *testing.T, privPEM []byte) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode(privPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("test key is not ECDSA")
	}
	return &ecKey.PublicKey
}
