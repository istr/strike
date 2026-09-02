package lane_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/lane"
)

// TestResolver_ADNIsAddressRejected pins the Go-side validateResolver
// behaviour: an address literal in the adn field passes CUE but is
// rejected by the validate-lane gate, so both `strike validate` and
// `strike run` (which pass every lane through the same gate) fail at
// the same point with the same diagnostic.
func TestResolver_ADNIsAddressRejected(t *testing.T) {
	path := filepath.Join("testdata", "peers", "invalid_resolver_adn_is_ip.yaml")
	err := parseAndValidate(t, path)
	if err == nil {
		t.Fatal("validation must reject an address literal in the resolver adn")
	}
	if !strings.Contains(err.Error(), "adn") {
		t.Errorf("error message must contain 'adn'; got: %v", err)
	}
	if !strings.Contains(err.Error(), "RFC 8310") {
		t.Errorf("error message must explain why an address is rejected; got: %v", err)
	}
}

// TestResolver_MissingRejected pins the CUE-side
// mandatory-field behaviour. The error message identifies
// the resolver field explicitly.
func TestResolver_MissingRejected(t *testing.T) {
	path := filepath.Join("testdata", "peers", "invalid_missing_resolver.yaml")
	err := parseAndValidate(t, path)
	if err == nil {
		t.Fatal("validation must reject lane without resolver")
	}
	if !strings.Contains(err.Error(), "resolver") {
		t.Errorf("error message must mention 'resolver'; got: %v", err)
	}
}

// TestResolver_ValidNoPort verifies that a resolver without an explicit
// port is accepted.
func TestResolver_ValidNoPort(t *testing.T) {
	yaml := []byte(`
name: resolver-ipv4
id: resolver-ipv4
secrets: {}
resolver:
  adn: one.one.one.one
  ip: 1.1.1.1
  trust:
    type: caBundle
    path: /etc/strike/resolver-ca.pem
oidc:
  issuer: "https://idp.example.com"
  audience: "strike"
  identity: "strike@example.com"
  trust:
    type: certFingerprint
    fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
keyless:
  endpoints:
    fulcio:
      url: "https://fulcio.example:5555"
      trust:
        type: certFingerprint
        fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
    rekor:
      url: "https://rekor.example:3003"
      trust:
        type: certFingerprint
        fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
    tsa:
      url: "https://tsa.example:3004"
      trust:
        type: certFingerprint
        fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
steps:
  - id: build
    image: docker.io/library/alpine@sha256:abababababababababababababababababababababababababababababababab
    args: ["true"]
    workdir: /work
    env: {}
    inputs: []
    secrets: []
    outputs:
      - id: out
        type: file
        path: x
  - id: deploy
    deploy:
      method:
        type: registry
        target:
          host: registry.example.com
          trust:
            type: certFingerprint
            fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
          name: app
      recording:
        preState:
          required: false
          captures: []
        postState:
          required: false
          captures: []
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
	if _, _, _, err := lane.Parse(fp); err != nil {
		t.Fatalf("Parse must accept a resolver without an explicit port: %v", err)
	}
}

// TestResolver_ValidWithPort verifies that a resolver with an
// explicit port is accepted.
func TestResolver_ValidWithPort(t *testing.T) {
	yaml := []byte(`
name: resolver-ipv4-port
id: resolver-ipv4-port
secrets: {}
resolver:
  adn: one.one.one.one
  ip: 1.1.1.1
  port: 853
  trust:
    type: caBundle
    path: /etc/strike/resolver-ca.pem
oidc:
  issuer: "https://idp.example.com"
  audience: "strike"
  identity: "strike@example.com"
  trust:
    type: certFingerprint
    fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
keyless:
  endpoints:
    fulcio:
      url: "https://fulcio.example:5555"
      trust:
        type: certFingerprint
        fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
    rekor:
      url: "https://rekor.example:3003"
      trust:
        type: certFingerprint
        fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
    tsa:
      url: "https://tsa.example:3004"
      trust:
        type: certFingerprint
        fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
steps:
  - id: build
    image: docker.io/library/alpine@sha256:abababababababababababababababababababababababababababababababab
    args: ["true"]
    workdir: /work
    env: {}
    inputs: []
    secrets: []
    outputs:
      - id: out
        type: file
        path: x
  - id: deploy
    deploy:
      method:
        type: registry
        target:
          host: registry.example.com
          trust:
            type: certFingerprint
            fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
          name: app
      recording:
        preState:
          required: false
          captures: []
        postState:
          required: false
          captures: []
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
	if _, _, _, err := lane.Parse(fp); err != nil {
		t.Fatalf("Parse must accept a resolver with an explicit port: %v", err)
	}
}
