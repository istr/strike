package deploy

import (
	"bytes"
	"context"
	"strings"

	"github.com/istr/strike/internal/container"
)

// SourceProvenance captures git metadata for the deployed source.
type SourceProvenance struct {
	Commit          string         `json:"commit"`
	Ref             string         `json:"ref"`
	Range           *CommitRange   `json:"range,omitempty"`
	Signers         []CommitSigner `json:"signers"`
	UnsignedCommits []string       `json:"unsigned_commits"`
	AllSigned       bool           `json:"all_signed"`
}

// CommitRange identifies the commit range since the previous known deploy.
type CommitRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// CommitSigner records a verified commit signature.
type CommitSigner struct {
	Commit      string `json:"commit"`
	Identity    string `json:"identity"`
	Method      string `json:"method"`
	Fingerprint string `json:"fingerprint,omitempty"`
	OIDCIssuer  string `json:"oidc_issuer,omitempty"`
	Verified    bool   `json:"verified"`
}

// captureSourceProvenance runs git containers to extract commit
// metadata and signature verification status from the source dir.
//
// Each git operation is a separate container run (exec form, no shell).
// Returns nil (not error) if no git repo is found or if any git
// command fails. Source provenance is best-effort enrichment.
func (d *Deployer) captureSourceProvenance( //nolint:unused // TODO(refactor-b/05): entire file deleted when provenance traversal lands
	ctx context.Context,
	sourceDirs []string,
	gitImage string,
) *SourceProvenance {
	for _, dir := range sourceDirs {
		prov := d.trySourceDir(ctx, dir, gitImage)
		if prov != nil {
			return prov
		}
	}
	return nil
}

// trySourceDir attempts to capture source provenance from a single directory.
func (d *Deployer) trySourceDir(ctx context.Context, dir, gitImage string) *SourceProvenance { //nolint:unused // see captureSourceProvenance
	if !isGitRepo(ctx, d.Engine, dir, gitImage) {
		return nil
	}

	commit := runGitCmd(ctx, d.Engine, dir, gitImage,
		"-C", "/src", "rev-parse", "HEAD")
	if commit == "" {
		return nil
	}

	// Try symbolic-ref first (branch name), then describe (tag), fall back to "detached".
	ref := runGitCmd(ctx, d.Engine, dir, gitImage,
		"-C", "/src", "symbolic-ref", "--short", "HEAD")
	if ref == "" {
		ref = runGitCmd(ctx, d.Engine, dir, gitImage,
			"-C", "/src", "describe", "--tags", "--exact-match")
	}
	if ref == "" {
		ref = "detached"
	}

	logOutput := runGitCmd(ctx, d.Engine, dir, gitImage,
		"-C", "/src", "log", "--format=%H|%G?|%GK|%GS|%aE", "HEAD")

	prov := parseGitLog(logOutput)
	if prov == nil {
		prov = &SourceProvenance{}
	}
	prov.Commit = commit
	prov.Ref = ref
	return prov
}

// gitRunOpts returns RunOpts configured for git container execution.
// Overrides entrypoint to "git" so commands work regardless of the image's
// default entrypoint. Uses -c safe.directory=/src to handle ownership
// differences from user namespace remapping.
func gitRunOpts(gitImage, dir string) container.RunOpts { //nolint:unused // see captureSourceProvenance
	opts := HardenedRunOpts()
	opts.Image = gitImage
	opts.Entrypoint = []string{"git"}
	opts.Env = map[string]string{"HOME": "/tmp"}
	opts.Mounts = []container.Mount{{Source: dir, Target: "/src", ReadOnly: true}}
	opts.Network = networkNone
	return opts
}

// gitArgs prepends -c safe.directory=/src to the given git arguments.
func gitArgs(args ...string) []string { //nolint:unused // see captureSourceProvenance
	return append([]string{"-c", "safe.directory=/src"}, args...)
}

// isGitRepo checks whether a directory contains a git repository.
func isGitRepo(ctx context.Context, engine container.Engine, dir, gitImage string) bool { //nolint:unused // see captureSourceProvenance
	var stdout bytes.Buffer
	opts := gitRunOpts(gitImage, dir)
	opts.Cmd = gitArgs("-C", "/src", "rev-parse", "--git-dir")
	opts.Stdout = &stdout
	opts.Stderr = &bytes.Buffer{}

	exitCode, err := engine.ContainerRun(ctx, opts)
	return err == nil && exitCode == 0
}

// runGitCmd runs a git command in a container and returns trimmed stdout.
// Each invocation is exec form (no shell). Returns empty string on failure.
func runGitCmd(ctx context.Context, engine container.Engine, dir, gitImage string, args ...string) string { //nolint:unused // see captureSourceProvenance
	var stdout, stderr bytes.Buffer
	opts := gitRunOpts(gitImage, dir)
	opts.Cmd = gitArgs(args...)
	opts.Stdout = &stdout
	opts.Stderr = &stderr

	exitCode, err := engine.ContainerRun(ctx, opts)
	if err != nil || exitCode != 0 {
		return ""
	}
	return strings.TrimSpace(stdout.String())
}

// parseGitLog parses the output of `git log --format=%H|%G?|%GK|%GS|%aE`.
// Returns nil if the output is empty.
func parseGitLog(output string) *SourceProvenance {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}

	prov := &SourceProvenance{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 5)
		if len(parts) < 5 {
			continue // malformed line, skip
		}

		commitHash := parts[0]
		sigStatus := parts[1]
		fingerprint := parts[2]
		signerName := parts[3]
		authorEmail := parts[4]

		switch sigStatus {
		case "G", "U", "X", "Y": // signed (good, unknown validity, expired, expired key)
			method := inferSignMethod(fingerprint)
			identity := signerName
			if identity == "" {
				identity = authorEmail
			}
			prov.Signers = append(prov.Signers, CommitSigner{
				Commit:      commitHash,
				Identity:    identity,
				Method:      method,
				Fingerprint: fingerprint,
				Verified:    sigStatus == "G",
			})
		default: // N, B, E, or unknown — treat as unsigned
			prov.UnsignedCommits = append(prov.UnsignedCommits, commitHash)
		}
	}

	prov.AllSigned = len(prov.UnsignedCommits) == 0 && len(prov.Signers) > 0
	return prov
}

// inferSignMethod determines the signature method from the fingerprint format.
func inferSignMethod(fingerprint string) string {
	switch {
	case strings.HasPrefix(fingerprint, "SHA256:"):
		return "ssh"
	case fingerprint == "":
		return "gpg"
	default:
		return "gpg"
	}
}
