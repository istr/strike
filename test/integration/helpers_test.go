package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/registry/regtest"
	"github.com/istr/strike/internal/testutil"
	"github.com/istr/strike/internal/transport"
)

// integrationCapsuleFields returns capsule-related Deployer fields for
// integration tests. portKeys lists every StepPorts key the test's step
// will look up.
func integrationCapsuleFields(t *testing.T, portKeys ...string) (ca *transport.EphemeralCA, look capsule.UpstreamLookupFunc, caVolume string, ports map[string]capsule.HostPorts) {
	t.Helper()
	var err error
	ca, err = transport.New("integration-test")
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	t.Cleanup(func() { testutil.CloseLog(t, ca, "integration CA") })

	caVolume = "strike-ca-integration-test"

	look = func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}

	ports = make(map[string]capsule.HostPorts, len(portKeys))
	base := uint16(17000)
	for i, k := range portKeys {
		ports[k] = capsule.HostPorts{
			Resolver: base + uint16(i)*2,
			Mediator: base + uint16(i)*2 + 1,
		}
	}
	return ca, look, caVolume, ports
}

// Digest-pinned image references matching lane.yaml.
const (
	goImage    = "cgr.dev/chainguard/go@sha256:4ec098b553c8d74d9f01925578660b2bfcdee4ef45e5ab082250cf9675a0e28b"
	staticBase = "cgr.dev/chainguard/static@sha256:2fdfacc8d61164aa9e20909dceec7cc28b9feb66580e8e1a65b9f2443c53b61b"
)

// needsEngine returns a live container.Engine or fails the test.
//
// By default, the helper probes the local podman socket via container.New().
// Set STRIKE_INTEGRATION=0 to skip integration tests unconditionally.
// A missing or unresponsive engine is a hard failure -- the operator must
// fix the prerequisite before integration tests can pass.
func needsEngine(t *testing.T) container.Engine {
	t.Helper()
	if os.Getenv("STRIKE_INTEGRATION") == "0" {
		t.Skip("integration tests disabled (STRIKE_INTEGRATION=0)")
	}
	engine, err := container.New()
	if err != nil {
		t.Fatalf("no container engine (is the podman socket running?): %v", err)
	}
	ctx := context.Background()
	if err := engine.Ping(ctx); err != nil {
		t.Fatalf("container engine not responding (check podman socket): %v", err)
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
				User:       lane.Ptr("65534:65534"),
			},
		},
		InputPaths:  map[string]string{"/app": binPath},
		OutputRoot:  outRoot,
		OutputName:  "image.tar",
		SigningKey:  keyPEM,
		KeyPassword: nil,
	})
	if packErr != nil {
		closer.Warn(outRoot, "packTestImage error cleanup")
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

// loadOCITar loads the main image from an OCI tar archive into the local
// container store and returns the manifest digest. Reimplemented here
// using only exported registry functions so that production code does not
// carry test-only helpers.
func loadOCITar(ctx context.Context, c *registry.Client, root *os.Root, relPath string) (lane.Digest, error) {
	f, err := root.Open(relPath)
	if err != nil {
		return lane.Digest{}, err
	}
	data, err := io.ReadAll(f)
	closer.Warn(f, "loadOCITar")
	if err != nil {
		return lane.Digest{}, err
	}

	tmpDir, err := os.MkdirTemp("", "strike-load-")
	if err != nil {
		return lane.Digest{}, err
	}
	defer closer.Remove(tmpDir, "loadOCITar")

	tmpRoot, err := os.OpenRoot(tmpDir)
	if err != nil {
		return lane.Digest{}, err
	}
	defer closer.Warn(tmpRoot, "loadOCITar root")

	if extractErr := regtest.ExtractTar(data, tmpRoot); extractErr != nil {
		return lane.Digest{}, fmt.Errorf("extract layout: %w", extractErr)
	}

	lp, err := layout.FromPath(tmpDir)
	if err != nil {
		return lane.Digest{}, fmt.Errorf("open layout: %w", err)
	}

	idx, err := lp.ImageIndex()
	if err != nil {
		return lane.Digest{}, fmt.Errorf("read index: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return lane.Digest{}, fmt.Errorf("read index manifest: %w", err)
	}

	var img v1.Image
	var descAnn map[string]string
	switch {
	case len(manifest.Manifests) == 1:
		img, err = idx.Image(manifest.Manifests[0].Digest)
		descAnn = manifest.Manifests[0].Annotations
	default:
		for _, desc := range manifest.Manifests {
			if _, ok := desc.Annotations["org.opencontainers.image.ref.name"]; ok {
				img, err = idx.Image(desc.Digest)
				descAnn = desc.Annotations
				break
			}
		}
	}
	if err != nil {
		return lane.Digest{}, err
	}
	if img == nil {
		return lane.Digest{}, fmt.Errorf("no annotated main image in %d-manifest archive", len(manifest.Manifests))
	}

	tarData, err := regtest.LayoutTar(img, descAnn)
	if err != nil {
		return lane.Digest{}, err
	}

	id, err := c.Engine.ImageLoad(ctx, bytes.NewReader(tarData))
	if err != nil {
		return lane.Digest{}, err
	}

	d, err := c.InspectDigest(ctx, id)
	if err != nil {
		return lane.Digest{}, err
	}

	localTag := "localhost/strike:" + d.Hex[:12]
	if tagErr := c.Engine.ImageTag(ctx, id, localTag); tagErr != nil {
		return lane.Digest{}, fmt.Errorf("image tag: %w", tagErr)
	}

	return d, nil
}
