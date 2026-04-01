package container_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/istr/strike/internal/container"
)

func newTestEngine(t *testing.T, handler http.Handler) container.Engine {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	eng, err := container.NewFromAddress("tcp://" + srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

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
			eng := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			eng := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			eng := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			eng := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
			eng := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			eng := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			eng := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	eng := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	eng := newTestEngine(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			"explicit container host",
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
