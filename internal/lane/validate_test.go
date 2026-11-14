package lane_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/testutil"
)

// parseAndValidate runs the full lane-structure gate -- Parse then
// ValidateLane -- and returns the first error, mirroring the CLI
// orchestration up to the point a lane is structurally rejected. Topology
// validation (Build, ValidateLeavesAreDeploys) is not part of this helper.
func parseAndValidate(t *testing.T, path string) error {
	t.Helper()
	fp, err := lane.NewFilePath(path)
	if err != nil {
		t.Fatalf("NewFilePath(%s): %v", path, err)
	}
	p, index, _, err := lane.Parse(fp)
	if err != nil {
		return err
	}
	return lane.ValidateLane(p, index)
}

// TestValidateLane_Reject exercises every invalid_*.yaml under
// testdata/validate/ through the full validation gate and asserts the
// intended error surfaces. The fixture list is glob-checked against the
// table, so adding a fixture without a table entry fails the test.
func TestValidateLane_Reject(t *testing.T) {
	tests := []struct {
		fixture      string
		wantContains string
	}{
		{"invalid_unknown_input_step.yaml", "unknown step"},
		{"invalid_input_output_not_found.yaml", "not found"},
		{"invalid_image_from_step_no_image_output.yaml", "declares no image output"},
		{"invalid_duplicate_output_id.yaml", "duplicate output id"},
		{"invalid_subpath_on_file_output.yaml", "subpath"},
		{"invalid_mount_overlap.yaml", "overlap"},
		{"invalid_mount_relative_path.yaml", "mount"},
		{"invalid_provenance_path_outside_output.yaml", "not within any declared output"},
		{"invalid_kubernetes_not_implemented.yaml", "not yet implemented"},
		{"invalid_image_output_on_container_step.yaml", "steps.0.image"},
		{"invalid_image_output_on_image_from_step.yaml", "steps.1.imageFromStep"},
		{"invalid_reproduced_by_unknown_step.yaml", "reproducedBy references unknown step"},
		{"invalid_reproduced_by_no_image_output.yaml", `reproducedBy "compile" declares no image output`},
		{"invalid_reproduced_by_image_arm.yaml", `reproducedBy "build" names the image arm`},
		{"invalid_oidc_identity_not_uri.yaml", "oidc identity"},
		{"invalid_sbom_signer_identity_not_uri.yaml", "baseSbomSigners[0] identity"},
		{"invalid_registry_undeclared.yaml", "registry images.example.com is not declared in registries or as a deploy target"},
		{"invalid_registry_declared_default_port.yaml", "registries[0].registry: write images.example.com, not images.example.com:443"},
		{"invalid_registry_ref_default_port.yaml", "pack base \"images.example.com:443/library/golang"},
		{"invalid_registry_target_default_port.yaml", "deploy step \"deploy\" target: write registry.example.com, not registry.example.com:443"},
		{"invalid_registry_uppercase_ref.yaml", "the registry host in an image reference must be lowercase"},
		{"invalid_registry_docker_io.yaml", "the registry dialed is index.docker.io"},
		{"invalid_registry_no_host.yaml", "step \"clone\" image \"alpine@sha256:"},
		{"invalid_registry_storage_ref.yaml", "a storage of registry images.example.com"},
		{"invalid_registry_target_declared.yaml", "registries[1].registry: registry registry.example.com already declared as target in step(s) \"deploy\""},
		{"invalid_registry_duplicate.yaml", "registries[0].storages[0]: images.example.com is declared more than once"},
		{"invalid_registry_anchor_not_ca.yaml", "registries[0].registry \"images.example.com\": rootca anchor is not a CA certificate"},
		{"invalid_registry_capture_undeclared.yaml", "step \"deploy\" capture \"version\" image"},
		{"invalid_registry_unparseable_ref.yaml", "pack base \"images.example.com/library/Golang"},
		{"invalid_registry_target_token_differs.yaml", "deploy step \"deploy-2\" target registry.example.com declares another credential token (\"registry-token-2\") than deploy step \"deploy\""},
		{"invalid_registry_target_anchor_differs.yaml", "deploy step \"deploy-2\" target registry.example.com declares another trust anchor than deploy step \"deploy\""},
	}

	matches, err := filepath.Glob("testdata/validate/invalid_*.yaml")
	if err != nil {
		t.Fatalf("glob invalid fixtures: %v", err)
	}
	have := map[string]bool{}
	for _, m := range matches {
		have[filepath.Base(m)] = true
	}
	for _, tc := range tests {
		delete(have, tc.fixture)
	}
	if len(have) > 0 {
		t.Errorf("invalid fixtures on disk not covered by table: %v", have)
	}

	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			path := filepath.Join("testdata", "validate", tc.fixture)
			err := parseAndValidate(t, path)
			if err == nil {
				t.Fatalf("validate(%s): expected error, got nil", path)
			}
			if !strings.Contains(err.Error(), tc.wantContains) {
				t.Errorf("validate(%s): error %q does not contain %q",
					path, err.Error(), tc.wantContains)
			}
		})
	}
}

// TestValidateLane_RejectOIDCDeclarations derives each case from the valid
// deploy fixture by one text replacement and asserts the declaration check
// that rejects it: the source-pin minimum, the URI-reference grammar of the
// oidc and base-SBOM signer pins, the builder token's declaration and
// confinement to the deploy, and the same for the token the registry
// credential names, which is never the builder token (ADR-058 D3).
func TestValidateLane_RejectOIDCDeclarations(t *testing.T) {
	base, err := fs.ReadFile(os.DirFS("testdata"), "valid_deploy_minimal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	const refPin = "    sourceRepositoryRef: \"refs/heads/main\"\n"
	tests := []struct {
		name         string
		old          string
		new          string
		wantContains string
	}{
		{"no source pin", refPin, "    runnerEnvironment: \"self-hosted\"\n", "declare sourceRepositoryRef or sourceRepositoryDigest"},
		{"oidc uri pin with space", refPin, refPin + "    sourceRepositoryURI: \"https://forge.example/a b\"\n", "oidc extensions sourceRepositoryURI"},
		{"oidc build config pin with space", refPin, refPin + "    sourceRepositoryURI: \"https://forge.example/o/r\"\n    buildConfigURI: \"https://forge.example/a b\"\n", "oidc extensions buildConfigURI"},
		{"undeclared token", "  token: builder-token\n", "  token: other-token\n", "oidc token \"other-token\" is not declared"},
		{"token reaches a step", "    secrets: []\n", "    secrets: [{name: builder-token, env: TOKEN}]\n", "is the oidc token"},
		{"undeclared registry token", "            token: registry-token\n", "            token: other-token\n", "registry token \"other-token\" is not declared"},
		{"registry token reaches a step", "    secrets: []\n", "    secrets: [{name: registry-token, env: TOKEN}]\n", "is the registry token"},
		{"registry credential names the oidc token", "            token: registry-token\n", "            token: builder-token\n", "names the oidc token \"builder-token\""},
		{"signer uri pin with space", "steps:\n", "baseSbomSigners:\n  - issuer: \"https://accounts.google.com\"\n    identity: \"sbom@example.com\"\n    extensions:\n      sourceRepositoryURI: \"https://forge.example/a b\"\nsteps:\n", "baseSbomSigners[0] extensions sourceRepositoryURI"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(string(base), tc.old) {
				t.Fatalf("fixture does not contain %q", tc.old)
			}
			path := filepath.Join(t.TempDir(), "lane.yaml")
			if err := os.WriteFile(path, []byte(strings.Replace(string(base), tc.old, tc.new, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			err := parseAndValidate(t, path)
			if err == nil || !strings.Contains(err.Error(), tc.wantContains) {
				t.Fatalf("err = %v, want an error containing %q", err, tc.wantContains)
			}
		})
	}
}

// TestParse_OIDCExtensionGrammar proves the schema grammars of the pin types:
// a ref outside git check-ref-format, a digest that is not a commit, and a
// runner environment outside the label grammar fail at parse.
func TestParse_OIDCExtensionGrammar(t *testing.T) {
	base, err := fs.ReadFile(os.DirFS("testdata"), "valid_deploy_minimal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	const refPin = "    sourceRepositoryRef: \"refs/heads/main\"\n"
	for _, pin := range []string{
		"    sourceRepositoryRef: \"refs/heads/a..b\"\n",
		refPin + "    sourceRepositoryDigest: \"abc123\"\n",
		refPin + "    runnerEnvironment: \"Self-Hosted\"\n",
	} {
		path := filepath.Join(t.TempDir(), "lane.yaml")
		if err := os.WriteFile(path, []byte(strings.Replace(string(base), refPin, pin, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		fp, err := lane.NewFilePath(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := lane.Parse(fp); err == nil || !strings.Contains(err.Error(), "validation") {
			t.Errorf("pin %q: err = %v, want a schema validation error", pin, err)
		}
	}
}

// TestParse_RegistryCredentialGrammar proves the credential's schema: a
// registry target without one, a credential type outside the vocabulary, and
// a credential without the name of its token fail at parse (ADR-058 D1, D2).
func TestParse_RegistryCredentialGrammar(t *testing.T) {
	base, err := fs.ReadFile(os.DirFS("testdata"), "valid_deploy_minimal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	const credential = "          credential:\n            type: bearer\n            token: registry-token\n"
	if !strings.Contains(string(base), credential) {
		t.Fatalf("fixture does not contain %q", credential)
	}
	for _, replacement := range []string{
		"",
		"          credential:\n            type: basic\n            token: registry-token\n",
		"          credential:\n            type: bearer\n",
	} {
		path := filepath.Join(t.TempDir(), "lane.yaml")
		if err := os.WriteFile(path, []byte(strings.Replace(string(base), credential, replacement, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		fp, err := lane.NewFilePath(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := lane.Parse(fp); err == nil || !strings.Contains(err.Error(), "validation") {
			t.Errorf("credential %q: err = %v, want a schema validation error", replacement, err)
		}
	}
}

// TestValidateLane_RejectPeerDefaultPort pins that a step or deploy capture
// peer spelling out the default port of its protocol is rejected: 443 for
// https, 22 for ssh.
func TestValidateLane_RejectPeerDefaultPort(t *testing.T) {
	base, err := fs.ReadFile(os.DirFS("testdata"), "valid_force_run_minimal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	const forceRun = "    forceRun: true\n"
	const preState = "        preState:\n          required: false\n          captures: []\n"
	cert := "\"" + testutil.AnchorCertB64 + "\"\n"
	tests := []struct {
		name         string
		old          string
		new          string
		wantContains string
	}{
		{
			"https step peer on 443", forceRun,
			forceRun + "    peers:\n      - type: https\n        host: example.com:443\n        trust:\n          cert: " + cert,
			`step "clone" peer: write example.com, not example.com:443`,
		},
		{
			"ssh step peer on 22", forceRun,
			forceRun + "    peers:\n      - type: ssh\n        host: git.example.com:22\n        knownHosts:\n          - keyType: ssh-ed25519\n            key: AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
			`step "clone" peer: write git.example.com, not git.example.com:22`,
		},
		{
			"https capture peer on 443", preState,
			"        preState:\n          required: false\n          captures:\n            - id: version\n              image: images.example.com/library/busybox@sha256:" + strings.Repeat("ab", 32) + "\n              command: [\"version\"]\n              peers:\n                - type: https\n                  host: example.com:443\n                  trust:\n                    cert: " + cert,
			`step "deploy" capture "version" peer: write example.com, not example.com:443`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(string(base), tc.old) {
				t.Fatalf("fixture does not contain %q", tc.old)
			}
			path := filepath.Join(t.TempDir(), "lane.yaml")
			if err := os.WriteFile(path, []byte(strings.Replace(string(base), tc.old, tc.new, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			err := parseAndValidate(t, path)
			if err == nil || !strings.Contains(err.Error(), tc.wantContains) {
				t.Fatalf("err = %v, want an error containing %q", err, tc.wantContains)
			}
		})
	}
}
