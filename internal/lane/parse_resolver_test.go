package lane_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

// TestResolver_FQDNRejectedByParse pins the Go-side
// validateResolver behaviour: an FQDN passes CUE but is
// rejected by the early Go validation, so both `strike
// validate` and `strike run` (which call Parse identically)
// fail at the same point with the same diagnostic.
func TestResolver_FQDNRejectedByParse(t *testing.T) {
	path := filepath.Join("testdata", "peers", "invalid_resolver_fqdn_host.yaml")
	fp, fpErr := lane.NewFilePath(path)
	if fpErr != nil {
		t.Fatalf("NewFilePath: %v", fpErr)
	}
	_, err := lane.Parse(fp)
	if err == nil {
		t.Fatal("Parse must reject FQDN resolver host")
	}
	if !strings.Contains(err.Error(), "must be IP literal") {
		t.Errorf("error message must contain 'must be IP literal'; got: %v", err)
	}
	if !strings.Contains(err.Error(), "FQDNs are not allowed") {
		t.Errorf("error message must explain why FQDNs are rejected; got: %v", err)
	}
}

// TestResolver_MissingRejectedByParse pins the CUE-side
// mandatory-field behaviour. The error message identifies
// the resolver field explicitly.
func TestResolver_MissingRejectedByParse(t *testing.T) {
	path := filepath.Join("testdata", "peers", "invalid_missing_resolver.yaml")
	fp, fpErr := lane.NewFilePath(path)
	if fpErr != nil {
		t.Fatalf("NewFilePath: %v", fpErr)
	}
	_, err := lane.Parse(fp)
	if err == nil {
		t.Fatal("Parse must reject lane without resolver")
	}
	if !strings.Contains(err.Error(), "resolver") {
		t.Errorf("error message must mention 'resolver'; got: %v", err)
	}
}

// TestResolver_ValidIPv4 verifies that a plain IPv4 (without port)
// is accepted.
func TestResolver_ValidIPv4(t *testing.T) {
	yaml := []byte(`
name: resolver-ipv4
lane_id: resolver-ipv4
registry: localhost:5555/test
secrets: {}
resolver:
  host: "1.1.1.1"
  trust:
    mode: cert_fingerprint
    fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
oidc:
  issuer: "https://idp.example.com"
  client_id: "strike"
  identity: "strike@example.com"
  trust:
    mode: cert_fingerprint
    fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
keyless:
  fulcio:
    url: "https://fulcio.example:5555"
    trust:
      mode: cert_fingerprint
      fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
  rekor:
    url: "https://rekor.example:3003"
    trust:
      mode: cert_fingerprint
      fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
  tsa:
    url: "https://tsa.example:3004"
    trust:
      mode: cert_fingerprint
      fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
steps:
  - name: build
    image: docker.io/library/alpine@sha256:abababababababababababababababababababababababababababababababab
    args: ["true"]
    workdir: /work
    env: {}
    inputs: []
    secrets: []
    outputs:
      - { name: out, type: file, path: x }
  - name: deploy
    deploy:
      method:
        type: registry
        source: localhost:5555/test/image:latest
        target: registry.example.com/app:latest
      artifacts: {}
      target:
        id: d1-minimal-target
        type: registry
        description: minimal deploy step for D1
      attestation:
        pre_state:
          required: false
          capture: []
        post_state:
          required: false
          capture: []
    args: []
    env: {}
    inputs: []
    secrets: []
    outputs: []
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "lane.yaml")
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	fp, fpErr := lane.NewFilePath(path)
	if fpErr != nil {
		t.Fatalf("NewFilePath: %v", fpErr)
	}
	if _, err := lane.Parse(fp); err != nil {
		t.Fatalf("Parse must accept IPv4-only resolver host: %v", err)
	}
}

// TestResolver_ValidIPv4WithPort verifies that an IPv4 with
// explicit port is accepted.
func TestResolver_ValidIPv4WithPort(t *testing.T) {
	yaml := []byte(`
name: resolver-ipv4-port
lane_id: resolver-ipv4-port
registry: localhost:5555/test
secrets: {}
resolver:
  host: "9.9.9.9:853"
  trust:
    mode: cert_fingerprint
    fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
oidc:
  issuer: "https://idp.example.com"
  client_id: "strike"
  identity: "strike@example.com"
  trust:
    mode: cert_fingerprint
    fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
keyless:
  fulcio:
    url: "https://fulcio.example:5555"
    trust:
      mode: cert_fingerprint
      fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
  rekor:
    url: "https://rekor.example:3003"
    trust:
      mode: cert_fingerprint
      fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
  tsa:
    url: "https://tsa.example:3004"
    trust:
      mode: cert_fingerprint
      fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
steps:
  - name: build
    image: docker.io/library/alpine@sha256:abababababababababababababababababababababababababababababababab
    args: ["true"]
    workdir: /work
    env: {}
    inputs: []
    secrets: []
    outputs:
      - { name: out, type: file, path: x }
  - name: deploy
    deploy:
      method:
        type: registry
        source: localhost:5555/test/image:latest
        target: registry.example.com/app:latest
      artifacts: {}
      target:
        id: d1-minimal-target
        type: registry
        description: minimal deploy step for D1
      attestation:
        pre_state:
          required: false
          capture: []
        post_state:
          required: false
          capture: []
    args: []
    env: {}
    inputs: []
    secrets: []
    outputs: []
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "lane.yaml")
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	fp, fpErr := lane.NewFilePath(path)
	if fpErr != nil {
		t.Fatalf("NewFilePath: %v", fpErr)
	}
	if _, err := lane.Parse(fp); err != nil {
		t.Fatalf("Parse must accept IPv4 with port resolver host: %v", err)
	}
}
