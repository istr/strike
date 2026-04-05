package integration_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/deploy"
	"github.com/istr/strike/internal/lane"
)

const networkNone = "none"

func TestSourceProvenance(t *testing.T) {
	engine := needsEngine(t)
	ctx := context.Background()

	ensureImage(t, engine, goImage)

	// Create a temp dir with a git repo via container.
	srcDir := containerTempDir(t)
	runGitInit(t, engine, srcDir)
	runGitAdd(t, engine, srcDir, "file.txt", "hello\n")
	runGitCommit(t, engine, srcDir, "first commit")

	// Deploy with source provenance.
	state := lane.NewState()
	if err := state.Register("build", "bin", lane.Artifact{
		Type:   "file",
		Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}); err != nil {
		t.Fatal(err)
	}

	step := sourceDeployStep(goImage)
	deployer := &deploy.Deployer{
		Engine:     engine,
		EngineID:   engine.Identity(),
		SourceDirs: []string{srcDir},
	}

	att, err := deployer.Execute(ctx, step, state)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

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
	if len(att.Source.UnsignedCommits) == 0 {
		t.Error("expected at least one unsigned commit")
	}
	t.Logf("source: commit=%s ref=%s unsigned=%d",
		att.Source.Commit[:12], att.Source.Ref, len(att.Source.UnsignedCommits))
}

func TestSourceProvenanceNoGitRepo(t *testing.T) {
	engine := needsEngine(t)
	ctx := context.Background()

	ensureImage(t, engine, goImage)

	// Empty temp dir — no .git.
	emptyDir := containerTempDir(t)

	state := lane.NewState()
	if err := state.Register("build", "bin", lane.Artifact{
		Type:   "file",
		Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}); err != nil {
		t.Fatal(err)
	}

	step := sourceDeployStep(goImage)
	deployer := &deploy.Deployer{
		Engine:     engine,
		EngineID:   engine.Identity(),
		SourceDirs: []string{emptyDir},
	}

	att, err := deployer.Execute(ctx, step, state)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	if att.Source != nil {
		t.Errorf("expected nil source provenance for non-git dir, got %+v", att.Source)
	}
}

// sourceDeployStep returns a deploy step configured for source provenance testing.
func sourceDeployStep(gitImageRef string) *lane.Step {
	return &lane.Step{
		Name: "deploy-source-test",
		Deploy: &lane.DeploySpec{
			Method: lane.DeployMethod{
				"type":       "custom",
				"image":      gitImageRef,
				"entrypoint": []any{"true"},
			},
			Artifacts: map[string]lane.ArtifactRef{
				"bin": {From: "build.bin"},
			},
			Target: lane.DeployTarget{
				Type:        "test",
				Description: "source provenance test",
			},
			Attestation: lane.AttestationSpec{
				PreState:  lane.StateCaptureSpec{Required: false},
				PostState: lane.StateCaptureSpec{Required: false},
				Drift:     lane.DriftSpec{Detect: false},
			},
			Source: &struct {
				Git_image lane.ImageRef `json:"git_image"` //nolint:revive // generated field name
			}{
				Git_image: lane.ImageRef(gitImageRef),
			},
		},
	}
}

// containerTempDir creates a temp dir accessible to containers via keep-id
// and registers cleanup that handles files owned by the mapped uid.
func containerTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "strike-test-")
	if err != nil {
		t.Fatal(err)
	}
	if chErr := os.Chmod(dir, 0o777); chErr != nil { //nolint:gosec // G302: world-accessible required for Podman keep-id userns mapping (container UID != host UID)
		t.Fatal(chErr)
	}
	t.Cleanup(func() {
		// Files created by containers with keep-id are owned by the mapped
		// UID (e.g. 100000). chmod makes them deletable by the host user.
		_ = filepath.Walk(dir, func(path string, _ os.FileInfo, _ error) error { //nolint:errcheck // best-effort cleanup; Walk error is non-fatal
			return os.Chmod(path, 0o777) //nolint:gosec // G302: required for userns cleanup (see containerTempDir doc)
		})
		_ = os.RemoveAll(dir) //nolint:errcheck // best-effort cleanup; test temp dir, non-fatal if removal fails
	})
	return dir
}

// gitOpts returns RunOpts for a git exec-form container run.
// Uses the full hardened security profile with keep-id.
// HOME is set to /tmp (writable via tmpfs) for git config.
// safe.directory=/repo handles ownership differences from userns mapping.
func gitOpts(dir string, writable bool) container.RunOpts {
	opts := container.DefaultSecureOpts()
	opts.Image = goImage
	opts.Entrypoint = []string{"git"}
	opts.Env = map[string]string{"HOME": "/tmp"}
	opts.Mounts = []container.Mount{{Source: dir, Target: "/repo", ReadOnly: !writable}}
	opts.Network = networkNone
	return opts
}

// safeArgs prepends -c safe.directory=/repo to git arguments.
func safeArgs(args ...string) []string {
	return append([]string{"-c", "safe.directory=/repo"}, args...)
}

// runGitInit initializes a git repo in a container (exec form, no shell).
func runGitInit(t *testing.T, engine container.Engine, dir string) {
	t.Helper()
	runGit(t, engine, dir, true, "init", "-b", "main", "/repo")
	runGit(t, engine, dir, true, "-C", "/repo", "config", "user.email", "test@strike.dev")
	runGit(t, engine, dir, true, "-C", "/repo", "config", "user.name", "strike-test")
}

// runGitAdd writes a file to the repo and stages it (exec form, no shell).
// Uses two container runs: one to write the file via tee, one to git add.
func runGitAdd(t *testing.T, engine container.Engine, dir, name, content string) {
	t.Helper()
	ctx := context.Background()

	var stderr bytes.Buffer
	opts := container.DefaultSecureOpts()
	opts.Image = goImage
	opts.Entrypoint = []string{"tee"}
	opts.Cmd = []string{"/repo/" + name}
	opts.Mounts = []container.Mount{{Source: dir, Target: "/repo"}}
	opts.Network = networkNone
	opts.Stdin = bytes.NewReader([]byte(content))
	opts.Stdout = &bytes.Buffer{}
	opts.Stderr = &stderr

	exitCode, err := engine.ContainerRun(ctx, opts)
	if err != nil || exitCode != 0 {
		t.Fatalf("tee %s: exit=%d err=%v stderr=%s", name, exitCode, err, stderr.String())
	}

	runGit(t, engine, dir, true, "-C", "/repo", "add", name)
}

// runGitCommit commits all staged changes (exec form, no shell).
func runGitCommit(t *testing.T, engine container.Engine, dir, msg string) {
	t.Helper()
	runGit(t, engine, dir, true, "-C", "/repo", "commit", "-m", msg)
}

// runGit executes a single git command in a container with exec form.
func runGit(t *testing.T, engine container.Engine, dir string, writable bool, args ...string) {
	t.Helper()
	ctx := context.Background()
	var stdout, stderr bytes.Buffer
	opts := gitOpts(dir, writable)
	opts.Cmd = safeArgs(args...)
	opts.Stdout = &stdout
	opts.Stderr = &stderr

	exitCode, err := engine.ContainerRun(ctx, opts)
	if err != nil || exitCode != 0 {
		t.Fatalf("git %v: exit=%d err=%v stdout=%s stderr=%s",
			args, exitCode, err, stdout.String(), stderr.String())
	}
}
