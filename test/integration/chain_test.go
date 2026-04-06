package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
)

// TestEndToEndChain validates the complete attestation chain:
// source -> build -> pack -> sign -> deploy -> signed attestation
// with source provenance.
func TestEndToEndChain(t *testing.T) {
	engine := needsEngine(t)
	ctx := context.Background()
	keyPEM := generateTestKey(t)

	ensureImage(t, engine, goImage)
	ensureImage(t, engine, staticBase)

	// --- Part 1: Source — git repo with the test Go program ---
	srcDir := containerTempDir(t)
	copyTestSource(t, srcDir)
	runGitInit(t, engine, srcDir)
	addTestSourceToGit(t, engine, srcDir)
	runGitCommit(t, engine, srcDir, "initial commit")

	// --- Part 2: Build — compile from git source ---
	outDir := containerTempDir(t)
	buildBinaryFrom(t, engine, srcDir, outDir)
	binPath := filepath.Join(outDir, "app")

	// --- Part 3: Pack — assemble and sign OCI image ---
	packDir := t.TempDir()
	packRoot, openErr := os.OpenRoot(packDir)
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer packRoot.Close() //nolint:errcheck // os.Root.Close on temp dir; error is not actionable in test

	packResult, err := executor.Pack(context.Background(), executor.PackOpts{
		Spec:        chainPackSpec(),
		InputPaths:  map[string]string{"build.app": binPath},
		OutputRoot:  packRoot,
		OutputName:  "image.tar",
		SigningKey:  keyPEM,
		KeyPassword: nil,
	})
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	imageDigest := packResult.Digest
	t.Logf("packed image: %s", imageDigest)

	regClient := &registry.Client{Engine: engine}
	if _, loadErr := regClient.LoadOCITar(ctx, packRoot, "image.tar"); loadErr != nil {
		t.Fatalf("load: %v", loadErr)
	}
	localTag := "localhost/strike:" + strings.TrimPrefix(imageDigest, "sha256:")[:12]

	// --- Part 4: Deploy — with attestation and source provenance ---
	state := lane.NewState()
	if regErr := state.Register("pack", "image", lane.Artifact{
		Type:   "image",
		Digest: imageDigest,
	}); regErr != nil {
		t.Fatal(regErr)
	}

	att := chainDeploy(t, engine, keyPEM, state, localTag, srcDir)

	// --- Part 5: Verify the complete chain ---
	verifyChain(t, att, imageDigest, keyPEM)
}

func chainPackSpec() *lane.PackSpec {
	return &lane.PackSpec{
		Base: lane.ImageRef(staticBase),
		Files: []lane.PackFile{
			{From: "build.app", Dest: "/app", Mode: 0o755},
		},
		Config: &lane.ImageConfig{
			Entrypoint: []string{"/app"},
			User:       "65534:65534",
		},
		Annotations: map[string]string{
			"org.opencontainers.image.source": "https://github.com/istr/strike",
		},
	}
}

func chainDeploy(
	t *testing.T, engine container.Engine,
	keyPEM []byte, state *lane.State, imageRef, srcDir string,
) *deploy.Attestation {
	t.Helper()
	ctx := context.Background()

	step := &lane.Step{
		Name: "deploy-e2e",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployMethod{
				"type":  "custom",
				"image": imageRef,
			},
			Artifacts: map[string]lane.ArtifactRef{
				"app": {From: "pack.image"},
			},
			Target: lane.DeployTarget{
				Type:        "test",
				Description: "end-to-end test",
			},
			Attestation: lane.AttestationSpec{
				PreState:  lane.StateCaptureSpec{Required: false},
				PostState: lane.StateCaptureSpec{Required: false},
				Drift:     lane.DriftSpec{Detect: false},
			},
			Source: &struct {
				Git_image lane.ImageRef `json:"git_image"` //nolint:revive // generated field name
			}{
				Git_image: lane.ImageRef(goImage),
			},
		},
	}

	deployer := &deploy.Deployer{
		Engine:      engine,
		EngineID:    engine.Identity(),
		SigningKey:  keyPEM,
		KeyPassword: nil,
		SourceDirs:  []string{srcDir},
	}

	att, err := deployer.Execute(ctx, step, state)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	return att
}

func verifyChain(t *testing.T, att *deploy.Attestation, imageDigest string, keyPEM []byte) {
	t.Helper()

	// A. Attestation validates against CUE schema.
	if err := deploy.ValidateAttestation(att); err != nil {
		t.Fatalf("attestation invalid: %v", err)
	}

	// B. Artifact digest matches packed image.
	if att.Artifacts["app"] != imageDigest {
		t.Errorf("artifact digest mismatch:\n  attestation: %s\n  packed:      %s",
			att.Artifacts["app"], imageDigest)
	}

	// C. Source provenance present.
	chainVerifySource(t, att)

	// D. Engine identity present.
	if att.Engine == nil {
		t.Error("engine identity missing")
	}

	// E. Deploy ID format.
	if len(att.DeployID) != 16 {
		t.Errorf("deploy ID length: %d, want 16", len(att.DeployID))
	}

	// F. Signature verifies + round-trip.
	chainVerifySignature(t, att, imageDigest, keyPEM)

	t.Logf("=== End-to-end chain verified ===")
	t.Logf("  source:      %s (%s)", att.Source.Commit[:12], att.Source.Ref)
	t.Logf("  image:       %s", imageDigest[:19])
	t.Logf("  deploy:      %s", att.DeployID)
	t.Logf("  signed:      yes (DSSE verified)")
	t.Logf("  all_signed:  %v", att.Source.AllSigned)
}

func chainVerifySource(t *testing.T, att *deploy.Attestation) {
	t.Helper()
	if att.Source == nil {
		t.Fatal("source provenance missing")
	}
	if len(att.Source.Commit) != 40 {
		t.Errorf("commit hash length: %d, want 40", len(att.Source.Commit))
	}
	if att.Source.Ref == "" {
		t.Error("source ref is empty")
	}
	if att.Source.AllSigned {
		t.Error("all_signed should be false (no signing configured)")
	}
	t.Logf("source: commit=%s ref=%s unsigned=%d",
		att.Source.Commit[:12], att.Source.Ref, len(att.Source.UnsignedCommits))
}

func chainVerifySignature(t *testing.T, att *deploy.Attestation, imageDigest string, keyPEM []byte) {
	t.Helper()
	if att.SignedEnvelope == nil {
		t.Fatal("expected signed envelope")
	}

	pubPEM := chainExtractPubKey(t, keyPEM)
	payload := chainVerifyDSSE(t, att.SignedEnvelope, pubPEM)

	var roundTripped deploy.Attestation
	if err := json.Unmarshal(payload, &roundTripped); err != nil {
		t.Fatalf("unmarshal round-tripped attestation: %v", err)
	}
	if roundTripped.DeployID != att.DeployID {
		t.Errorf("round-trip deploy ID mismatch: %s vs %s", roundTripped.DeployID, att.DeployID)
	}
	if roundTripped.Artifacts["app"] != imageDigest {
		t.Error("round-trip artifact digest mismatch")
	}
}

// chainVerifyDSSE verifies a DSSE envelope and returns the decoded payload.
func chainVerifyDSSE(t *testing.T, envelopeJSON, pubPEM []byte) []byte {
	t.Helper()

	var envelope struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		t.Fatalf("unmarshal DSSE envelope: %v", err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatalf("decode DSSE payload: %v", err)
	}

	pae := dssePayloadPAE(envelope.PayloadType, decoded)
	digest := sha256.Sum256(pae)

	pubKey := chainParsePubKey(t, pubPEM)
	for _, sig := range envelope.Signatures {
		sigBytes, decErr := base64.StdEncoding.DecodeString(sig.Sig)
		if decErr != nil || len(sigBytes) != 64 {
			continue
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if ecdsa.Verify(pubKey, digest[:], r, s) {
			return decoded
		}
	}
	t.Fatal("no valid DSSE signature found")
	return nil
}

func chainParsePubKey(t *testing.T, pubPEM []byte) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		t.Fatal("no PEM block in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, not ECDSA", pub)
	}
	return ecPub
}

func chainExtractPubKey(t *testing.T, privPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(privPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("not ECDSA")
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

// copyTestSource copies testdata/src/* into the target directory on the host.
func copyTestSource(t *testing.T, dstDir string) {
	t.Helper()
	srcDir := filepath.Join("testdata", "src")
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatalf("read testdata/src: %v", err)
	}
	for _, e := range entries {
		data, readErr := os.ReadFile(filepath.Join(srcDir, e.Name())) //nolint:gosec // G304: srcDir is hardcoded "testdata/src", not user input
		if readErr != nil {
			t.Fatalf("read %s: %v", e.Name(), readErr)
		}
		if writeErr := os.WriteFile(filepath.Join(dstDir, e.Name()), data, 0o666); writeErr != nil { //nolint:gosec // G306: world-readable required for Podman keep-id userns mapping
			t.Fatalf("write %s: %v", e.Name(), writeErr)
		}
	}
}

// addTestSourceToGit stages all files in the repo via git add (exec form).
func addTestSourceToGit(t *testing.T, engine container.Engine, dir string) {
	t.Helper()
	runGit(t, engine, dir, true, "-C", "/repo", "add", "-A")
}

// buildBinaryFrom compiles Go source from srcDir into outDir.
func buildBinaryFrom(t *testing.T, engine container.Engine, srcDir, outDir string) {
	t.Helper()
	ctx := context.Background()
	var stdout, stderr bytes.Buffer
	opts := container.DefaultSecureOpts()
	opts.Image = goImage
	opts.Cmd = []string{
		"build", "-C", "/src", "-trimpath",
		"-buildvcs=false", "-ldflags=-s -w",
		"-o", "/out/app", ".",
	}
	opts.Env = map[string]string{"CGO_ENABLED": "0", "GOCACHE": "/tmp/gocache", "GOPATH": "/tmp/gopath"}
	opts.Stdout = &stdout
	opts.Stderr = &stderr
	opts.Mounts = []container.Mount{
		{Source: srcDir, Target: "/src", ReadOnly: true},
		{Source: outDir, Target: "/out"},
	}

	exitCode, err := engine.ContainerRun(ctx, opts)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("build: exit code %d\nstdout: %s\nstderr: %s",
			exitCode, stdout.String(), stderr.String())
	}
}
