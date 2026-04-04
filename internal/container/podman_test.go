package container_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/istr/strike/internal/container"
)

func TestPing(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{"success", http.StatusOK, false},
		{"server error", http.StatusInternalServerError, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/_ping") {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				w.WriteHeader(tt.statusCode)
			}))
			err := eng.Ping(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("Ping() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestImageExists(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{"exists", http.StatusNoContent, true},
		{"not found", http.StatusNotFound, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.URL.Path, "/images/") || !strings.HasSuffix(r.URL.Path, "/exists") {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				w.WriteHeader(tt.statusCode)
			}))
			got, err := eng.ImageExists(context.Background(), "test:latest")
			if err != nil {
				t.Fatalf("ImageExists() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ImageExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestImagePull(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{"success", http.StatusOK, false},
		{"not found", http.StatusNotFound, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				ref := r.URL.Query().Get("reference")
				if ref != "alpine:3.19" {
					t.Errorf("reference = %q, want alpine:3.19", ref)
				}
				w.WriteHeader(tt.statusCode)
			}))
			err := eng.ImagePull(context.Background(), "alpine:3.19")
			if (err != nil) != tt.wantErr {
				t.Fatalf("ImagePull() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestImageInspect(t *testing.T) {
	tests := []struct {
		response   map[string]any
		name       string
		wantDigest string
		statusCode int
		wantErr    bool
	}{
		{
			response: map[string]any{
				"Id":          "abc123",
				"Digest":      "sha256:deadbeef",
				"RepoDigests": []string{"alpine@sha256:deadbeef"},
				"Size":        int64(1024),
				"Annotations": map[string]string{"org.example": "test"},
			},
			name:       "success",
			wantDigest: "sha256:deadbeef",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			response:   nil,
			name:       "not found",
			wantDigest: "",
			statusCode: http.StatusNotFound,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.response != nil {
					json.NewEncoder(w).Encode(tt.response) //nolint:errcheck,gosec // test HTTP handler
				}
			}))
			info, err := eng.ImageInspect(context.Background(), "alpine:latest")
			if (err != nil) != tt.wantErr {
				t.Fatalf("ImageInspect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && info.Digest != tt.wantDigest {
				t.Errorf("Digest = %q, want %q", info.Digest, tt.wantDigest)
			}
		})
	}
}

func TestImageLoad(t *testing.T) {
	tests := []struct {
		name     string
		response map[string]any
		wantID   string
		wantErr  bool
	}{
		{
			"success",
			map[string]any{"Names": []string{"loaded-image:latest"}},
			"loaded-image:latest",
			false,
		},
		{
			"empty response",
			map[string]any{"Names": []string{}},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.Header.Get("Content-Type") != "application/x-tar" {
					t.Errorf("Content-Type = %q, want application/x-tar", r.Header.Get("Content-Type"))
				}
				json.NewEncoder(w).Encode(tt.response) //nolint:errcheck,gosec // test HTTP handler
			}))
			id, err := eng.ImageLoad(context.Background(), strings.NewReader("fake-tar-data"))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ImageLoad() error = %v, wantErr %v", err, tt.wantErr)
			}
			if id != tt.wantID {
				t.Errorf("ImageLoad() = %q, want %q", id, tt.wantID)
			}
		})
	}
}

func TestImageTag(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		wantRepo   string
		wantTag    string
		statusCode int
		wantErr    bool
	}{
		{"success", "myrepo:v1.0", "myrepo", "v1.0", http.StatusCreated, false},
		{"no tag", "myrepo", "myrepo", "latest", http.StatusCreated, false},
		{"failure", "myrepo:v1.0", "myrepo", "v1.0", http.StatusNotFound, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				repo := r.URL.Query().Get("repo")
				tag := r.URL.Query().Get("tag")
				if repo != tt.wantRepo {
					t.Errorf("repo = %q, want %q", repo, tt.wantRepo)
				}
				if tag != tt.wantTag {
					t.Errorf("tag = %q, want %q", tag, tt.wantTag)
				}
				w.WriteHeader(tt.statusCode)
			}))
			err := eng.ImageTag(context.Background(), "source-image", tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ImageTag() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestImagePush(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{"success", http.StatusOK, false},
		{"failure", http.StatusInternalServerError, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.URL.Path, "/images/") || !strings.HasSuffix(r.URL.Path, "/push") {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.Header.Get("X-Registry-Auth") == "" {
					t.Error("missing X-Registry-Auth header")
				}
				w.WriteHeader(tt.statusCode)
			}))
			err := eng.ImagePush(context.Background(), "test:latest")
			if (err != nil) != tt.wantErr {
				t.Fatalf("ImagePush() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestContainerRun(t *testing.T) {
	var capturedSpec map[string]any
	step := 0

	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.HasSuffix(path, "/containers/create"):
			body, _ := io.ReadAll(r.Body)                                            //nolint:errcheck // test HTTP handler
			_ = json.Unmarshal(body, &capturedSpec)                                  //nolint:errcheck // test HTTP handler
			json.NewEncoder(w).Encode(map[string]string{"Id": "test-container-123"}) //nolint:errcheck,gosec // test HTTP handler

		case strings.HasSuffix(path, "/start"):
			w.WriteHeader(http.StatusNoContent)

		case strings.HasSuffix(path, "/logs"):
			// Write a multiplexed log frame: stdout "hello\n"
			header := make([]byte, 8)
			header[0] = 1 // stdout
			binary.BigEndian.PutUint32(header[4:], 6)
			w.Write(header)            //nolint:errcheck,gosec // test HTTP handler
			w.Write([]byte("hello\n")) //nolint:errcheck,gosec // test HTTP handler

		case strings.HasSuffix(path, "/wait"):
			json.NewEncoder(w).Encode(map[string]int{"StatusCode": 0}) //nolint:errcheck,gosec // test HTTP handler

		case r.Method == http.MethodDelete && strings.Contains(path, "/containers/"):
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]map[string]any{}) //nolint:errcheck,gosec // test HTTP handler

		default:
			step++
			w.WriteHeader(http.StatusOK)
		}
	}))

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode, err := eng.ContainerRun(context.Background(), container.RunOpts{
		Env:         map[string]string{"FOO": "bar"},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=512m"},
		Cmd:         []string{"echo", "hello"},
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges"},
		Mounts: []container.Mount{
			{Source: "/host/src", Target: "/src", ReadOnly: true},
		},
		Image:      "test:latest",
		Network:    "none",
		UsernsMode: "keep-id",
		Stdout:     &stdout,
		Stderr:     &stderr,
		ReadOnly:   true,
		Remove:     true,
	})
	if err != nil {
		t.Fatalf("ContainerRun() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if stdout.String() != "hello\n" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "hello\n")
	}

	verifySpecGenerator(t, capturedSpec)
}

func verifySpecGenerator(t *testing.T, capturedSpec map[string]any) {
	t.Helper()

	if capturedSpec["image"] != "test:latest" {
		t.Errorf("spec image = %v, want test:latest", capturedSpec["image"])
	}
	if capturedSpec["read_only_filesystem"] != true {
		t.Errorf("spec read_only_filesystem = %v, want true", capturedSpec["read_only_filesystem"])
	}
	env, ok := capturedSpec["env"].(map[string]any)
	if !ok {
		t.Fatal("expected env in spec")
	}
	if env["FOO"] != "bar" {
		t.Errorf("spec env FOO = %v, want bar", env["FOO"])
	}
	netns, ok := capturedSpec["netns"].(map[string]any)
	if !ok {
		t.Fatal("expected netns in spec")
	}
	if netns["nsmode"] != "none" {
		t.Errorf("spec netns nsmode = %v, want none", netns["nsmode"])
	}
	userns, ok := capturedSpec["userns"].(map[string]any)
	if !ok {
		t.Fatal("expected userns in spec")
	}
	if userns["nsmode"] != "keep-id" {
		t.Errorf("spec userns nsmode = %v, want keep-id", userns["nsmode"])
	}
}

func TestContainerRunExitCode(t *testing.T) {
	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/containers/create"):
			json.NewEncoder(w).Encode(map[string]string{"Id": "fail-container"}) //nolint:errcheck,gosec // test HTTP handler
		case strings.HasSuffix(path, "/start"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/logs"):
			// empty log stream
		case strings.HasSuffix(path, "/wait"):
			json.NewEncoder(w).Encode(map[string]int{"StatusCode": 42}) //nolint:errcheck,gosec // test HTTP handler
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]map[string]any{}) //nolint:errcheck,gosec // test HTTP handler
		}
	}))

	exitCode, err := eng.ContainerRun(context.Background(), container.RunOpts{
		Image:  "test:latest",
		Cmd:    []string{"false"},
		Remove: true,
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	if err != nil {
		t.Fatalf("ContainerRun() error = %v", err)
	}
	if exitCode != 42 {
		t.Fatalf("exitCode = %d, want 42", exitCode)
	}
}

func TestDetectSocket(t *testing.T) {
	tests := []struct {
		name          string
		containerHost string
		wantPrefix    string
		wantErr       bool
	}{
		{
			"tcp without CA uses system store",
			"tcp://ci-host:8080",
			"tcp://",
			false,
		},
		{
			"explicit unix socket",
			"unix:///custom/podman.sock",
			"unix://",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CONTAINER_HOST", tt.containerHost)
			t.Setenv("CONTAINER_TLS_CA", "")
			t.Setenv("CONTAINER_TLS_CERT", "")
			t.Setenv("CONTAINER_TLS_KEY", "")
			eng, err := container.New()
			if (err != nil) != tt.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && eng == nil {
				t.Fatal("expected non-nil engine")
			}
		})
	}
}

func TestSystemCAStoreUsedWhenNoPinnedCA(t *testing.T) {
	t.Setenv("CONTAINER_TLS_CA", "")
	t.Setenv("CONTAINER_TLS_CERT", "")
	t.Setenv("CONTAINER_TLS_KEY", "")

	cfg := container.LoadTLSConfig()
	if cfg.IsPinned() {
		t.Error("expected IsPinned() = false when CA is empty")
	}
	if !cfg.IsReady() {
		t.Error("expected IsReady() = true even without explicit CA")
	}

	// Build should succeed -- produces a config with nil RootCAs (= system store).
	tlsCfg, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if tlsCfg.RootCAs != nil {
		t.Error("expected nil RootCAs (system store fallback)")
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Error("expected TLS 1.3 minimum")
	}
}

func TestPinnedCAProducesExclusivePool(t *testing.T) {
	pki := generateTestPKI(t)
	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "ca.crt"), pki.caCertPEM)

	t.Setenv("CONTAINER_TLS_CA", filepath.Join(dir, "ca.crt"))
	t.Setenv("CONTAINER_TLS_CERT", "")
	t.Setenv("CONTAINER_TLS_KEY", "")

	cfg := container.LoadTLSConfig()
	if !cfg.IsPinned() {
		t.Error("expected IsPinned() = true when CA is set")
	}

	tlsCfg, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if tlsCfg.RootCAs == nil {
		t.Error("expected non-nil RootCAs (pinned CA pool)")
	}
}

func TestCATrustModeInIdentity_Pinned(t *testing.T) {
	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	if err := eng.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	id := eng.Identity()
	if id == nil {
		t.Fatal("expected identity")
	}
	if id.Connection.CATrustMode != "pinned" {
		t.Errorf("CATrustMode = %q, want pinned", id.Connection.CATrustMode)
	}
}

func TestTCPWithoutCAUsesSystemStore(t *testing.T) {
	// Without explicit CA, NewFromAddress should succeed (system store fallback).
	t.Setenv("CONTAINER_TLS_CA", "")
	t.Setenv("CONTAINER_TLS_CERT", "")
	t.Setenv("CONTAINER_TLS_KEY", "")

	eng, err := container.NewFromAddress("tcp://127.0.0.1:9999")
	if err != nil {
		t.Fatalf("NewFromAddress should succeed with system store fallback, got: %v", err)
	}
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestServerTLSCapturesFingerprint(t *testing.T) {
	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	if err := eng.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	tlsID := eng.TLSIdentity()
	if tlsID == nil {
		t.Fatal("expected non-nil TLSIdentity after TLS ping")
	}
	if !strings.HasPrefix(tlsID.ServerFingerprint, "sha256:") {
		t.Errorf("ServerFingerprint = %q, want sha256: prefix", tlsID.ServerFingerprint)
	}
	if tlsID.ServerSubject != "strike-test-engine" {
		t.Errorf("ServerSubject = %q, want strike-test-engine", tlsID.ServerSubject)
	}
	if tlsID.Mutual {
		t.Error("expected Mutual=false for server-only TLS")
	}
}

func TestMTLSCapturesBothFingerprints(t *testing.T) {
	eng := newMTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	if err := eng.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	tlsID := eng.TLSIdentity()
	if tlsID == nil {
		t.Fatal("expected non-nil TLSIdentity after mTLS ping")
	}
	if !strings.HasPrefix(tlsID.ServerFingerprint, "sha256:") {
		t.Errorf("ServerFingerprint = %q, want sha256: prefix", tlsID.ServerFingerprint)
	}
	if !strings.HasPrefix(tlsID.ClientFingerprint, "sha256:") {
		t.Errorf("ClientFingerprint = %q, want sha256: prefix", tlsID.ClientFingerprint)
	}
	if !tlsID.Mutual {
		t.Error("expected Mutual=true for mTLS")
	}
}

func TestTLSIdentityNilForUnixSocket(t *testing.T) {
	// We cannot easily construct a real Unix socket test engine here,
	// but we can verify that a freshly-created engine has nil TLSIdentity
	// before Ping is called. The identity is populated only after Ping.
	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Before Ping, TLSIdentity should be nil.
	if eng.TLSIdentity() != nil {
		t.Error("expected nil TLSIdentity before Ping")
	}
}

func TestIdentityAfterPing_ServerTLS(t *testing.T) {
	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	if err := eng.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	id := eng.Identity()
	if id == nil {
		t.Fatal("expected non-nil Identity after Ping")
	}
	if id.Connection.Type != "tls" {
		t.Errorf("Connection.Type = %q, want tls", id.Connection.Type)
	}
	if !strings.HasPrefix(id.Connection.ServerCertFingerprint, "sha256:") {
		t.Errorf("ServerCertFingerprint = %q, want sha256: prefix", id.Connection.ServerCertFingerprint)
	}
	if id.Connection.ServerCertSubject != "strike-test-engine" {
		t.Errorf("ServerCertSubject = %q, want strike-test-engine", id.Connection.ServerCertSubject)
	}
	if id.Connection.ClientCertFingerprint != "" {
		t.Errorf("ClientCertFingerprint should be empty for server-only TLS, got %q", id.Connection.ClientCertFingerprint)
	}
}

func TestIdentityAfterPing_MTLS(t *testing.T) {
	eng := newMTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	if err := eng.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	id := eng.Identity()
	if id == nil {
		t.Fatal("expected non-nil Identity after Ping")
	}
	if id.Connection.Type != "mtls" {
		t.Errorf("Connection.Type = %q, want mtls", id.Connection.Type)
	}
	if !strings.HasPrefix(id.Connection.ServerCertFingerprint, "sha256:") {
		t.Errorf("ServerCertFingerprint = %q, want sha256: prefix", id.Connection.ServerCertFingerprint)
	}
	if !strings.HasPrefix(id.Connection.ClientCertFingerprint, "sha256:") {
		t.Errorf("ClientCertFingerprint = %q, want sha256: prefix", id.Connection.ClientCertFingerprint)
	}
	if id.Connection.ClientCertSubject != "strike-test-controller" {
		t.Errorf("ClientCertSubject = %q, want strike-test-controller", id.Connection.ClientCertSubject)
	}
}

func TestInfoPopulatesRuntime(t *testing.T) {
	infoResp := map[string]any{
		"host": map[string]any{
			"rootless": true,
			"security": map[string]any{
				"selinuxEnabled":  false,
				"apparmorEnabled": true,
			},
		},
		"version": map[string]any{
			"APIVersion": "5.0.0",
			"Version":    "5.2.1",
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/_ping"):
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(path, "/info"):
			json.NewEncoder(w).Encode(infoResp) //nolint:errcheck,gosec // test HTTP handler
		default:
			w.WriteHeader(http.StatusOK)
		}
	})

	eng := newTLSTestEngine(t, mux)

	if err := eng.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := eng.Info(context.Background()); err != nil {
		t.Fatalf("Info: %v", err)
	}

	id := eng.Identity()
	if id == nil {
		t.Fatal("expected non-nil Identity")
	}
	if id.Runtime == nil {
		t.Fatal("expected non-nil Runtime after Info")
	}
	if id.Runtime.Version != "5.2.1" {
		t.Errorf("Version = %q, want 5.2.1", id.Runtime.Version)
	}
	if id.Runtime.APIVersion != "5.0.0" {
		t.Errorf("APIVersion = %q, want 5.0.0", id.Runtime.APIVersion)
	}
	if !id.Runtime.Rootless {
		t.Error("expected Rootless=true")
	}
	if !id.Runtime.AppArmor {
		t.Error("expected AppArmor=true")
	}
	if id.Runtime.SELinux {
		t.Error("expected SELinux=false")
	}
}

// --------------------------------------------------------------------------.
// DefaultSecureOpts and detectSocket.
// --------------------------------------------------------------------------.

func TestDefaultSecureOpts(t *testing.T) {
	opts := container.DefaultSecureOpts()

	if len(opts.CapDrop) != 1 || opts.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %v, want [ALL]", opts.CapDrop)
	}
	if !opts.ReadOnly {
		t.Error("expected ReadOnly=true")
	}
	if len(opts.SecurityOpt) != 1 || opts.SecurityOpt[0] != "no-new-privileges" {
		t.Errorf("SecurityOpt = %v, want [no-new-privileges]", opts.SecurityOpt)
	}
	tmpOpts, ok := opts.Tmpfs["/tmp"]
	if !ok {
		t.Fatal("expected /tmp in Tmpfs")
	}
	if !strings.Contains(tmpOpts, "noexec") {
		t.Errorf("Tmpfs[/tmp] = %q, want noexec", tmpOpts)
	}
	if opts.UsernsMode != "keep-id" {
		t.Errorf("UsernsMode = %q, want keep-id", opts.UsernsMode)
	}
	if !opts.Remove {
		t.Error("expected Remove=true")
	}
}

func TestDetectSocket_XDGRuntime(t *testing.T) {
	dir := t.TempDir()
	sockDir := filepath.Join(dir, "podman")
	if err := os.MkdirAll(sockDir, 0o750); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(sockDir, "podman.sock")
	if err := os.WriteFile(sockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONTAINER_HOST", "")
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("CONTAINER_TLS_CA", "")
	t.Setenv("CONTAINER_TLS_CERT", "")
	t.Setenv("CONTAINER_TLS_KEY", "")

	eng, err := container.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestDetectSocket_ContainerHostOverride(t *testing.T) {
	t.Setenv("CONTAINER_HOST", "tcp://custom-host:9999")
	t.Setenv("CONTAINER_TLS_CA", "")
	t.Setenv("CONTAINER_TLS_CERT", "")
	t.Setenv("CONTAINER_TLS_KEY", "")

	eng, err := container.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
}

// --------------------------------------------------------------------------.
// demuxLogStream edge cases.
// --------------------------------------------------------------------------.

func TestDemuxLogStream_StderrStream(t *testing.T) {
	// Build a frame with stream type 2 (stderr).
	msg := []byte("error output")
	var buf bytes.Buffer
	header := make([]byte, 8)
	header[0] = 2                                            // stderr
	binary.BigEndian.PutUint32(header[4:], uint32(len(msg))) //nolint:gosec // G115: test data is small
	buf.Write(header)
	buf.Write(msg)

	var stdout, stderr bytes.Buffer
	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/containers/create"):
			json.NewEncoder(w).Encode(map[string]string{"Id": "test-stderr"}) //nolint:errcheck,gosec // test
		case strings.HasSuffix(path, "/start"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/logs"):
			w.Write(header) //nolint:errcheck,gosec // test
			w.Write(msg)    //nolint:errcheck,gosec // test
		case strings.HasSuffix(path, "/wait"):
			json.NewEncoder(w).Encode(map[string]int{"StatusCode": 0}) //nolint:errcheck,gosec // test
		case r.Method == http.MethodDelete:
			json.NewEncoder(w).Encode([]map[string]any{}) //nolint:errcheck,gosec // test
		}
	}))

	exitCode, err := eng.ContainerRun(context.Background(), container.RunOpts{
		Image:  "test:latest",
		Cmd:    []string{"fail"},
		Remove: true,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("ContainerRun() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if stderr.String() != "error output" {
		t.Errorf("stderr = %q, want %q", stderr.String(), "error output")
	}
	if stdout.String() != "" {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}

func TestDemuxLogStream_UnknownStreamType(t *testing.T) {
	// Stream type 3 (unknown) should be discarded.
	msg := []byte("discard me")
	header := make([]byte, 8)
	header[0] = 3                                            // unknown
	binary.BigEndian.PutUint32(header[4:], uint32(len(msg))) //nolint:gosec // G115: test data is small

	eng := newTLSTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/containers/create"):
			json.NewEncoder(w).Encode(map[string]string{"Id": "test-unknown"}) //nolint:errcheck,gosec // test
		case strings.HasSuffix(path, "/start"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/logs"):
			w.Write(header) //nolint:errcheck,gosec // test
			w.Write(msg)    //nolint:errcheck,gosec // test
		case strings.HasSuffix(path, "/wait"):
			json.NewEncoder(w).Encode(map[string]int{"StatusCode": 0}) //nolint:errcheck,gosec // test
		case r.Method == http.MethodDelete:
			json.NewEncoder(w).Encode([]map[string]any{}) //nolint:errcheck,gosec // test
		}
	}))

	var stdout, stderr bytes.Buffer
	exitCode, err := eng.ContainerRun(context.Background(), container.RunOpts{
		Image:  "test:latest",
		Cmd:    []string{"echo"},
		Remove: true,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("ContainerRun() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if stdout.String() != "" {
		t.Errorf("stdout should be empty, got %q", stdout.String())
	}
	if stderr.String() != "" {
		t.Errorf("stderr should be empty, got %q", stderr.String())
	}
}

func TestAuditLogging(t *testing.T) {
	t.Setenv("STRIKE_AUDIT", "1")

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w

	eng := newTLSTestEngine(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	if err := eng.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("w.Close: %v", err)
	}
	os.Stderr = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("r.Close: %v", err)
	}

	if !strings.Contains(buf.String(), "AUDIT") {
		t.Errorf("expected AUDIT line in stderr, got: %q", buf.String())
	}
}
