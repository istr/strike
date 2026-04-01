// Package container provides a thin client for container engine REST APIs.
// It eliminates exec.Command as an attack vector by communicating over
// Unix socket or TCP instead of spawning subprocesses.
package container

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// Engine is the interface for container engine operations.
// Implementations must be safe for concurrent use.
type Engine interface {
	// ImageExists checks if an image exists in the local store.
	ImageExists(ctx context.Context, ref string) (bool, error)

	// ImagePull fetches an image from a remote registry.
	ImagePull(ctx context.Context, ref string) error

	// ImagePush pushes a local image to a remote registry.
	ImagePush(ctx context.Context, name string) error

	// ImageLoad loads an OCI tar archive into the local store.
	// Returns the image ID.
	ImageLoad(ctx context.Context, input io.Reader) (string, error)

	// ImageInspect returns metadata for a local image.
	ImageInspect(ctx context.Context, ref string) (*ImageInfo, error)

	// ImageTag adds a tag to an existing image.
	ImageTag(ctx context.Context, source, target string) error

	// ContainerRun creates, starts, waits for, and removes a container.
	// Stdout and stderr are streamed to the provided writers.
	// Returns the exit code.
	ContainerRun(ctx context.Context, opts RunOpts) (int, error)

	// Ping verifies the engine is reachable.
	Ping(ctx context.Context) error
}

// ImageInfo holds metadata from image inspection.
type ImageInfo struct {
	ID          string
	Digest      string // "sha256:..."
	RepoDigests []string
	Annotations map[string]string
	Size        int64
}

// RunOpts configures a container execution.
type RunOpts struct {
	Image       string
	Cmd         []string
	Env         map[string]string // all env vars including secrets
	Mounts      []Mount
	Network     string // "none", "host", or "" (default bridge)
	CapDrop     []string
	ReadOnly    bool
	SecurityOpt []string
	Tmpfs       map[string]string // path -> options
	UsernsMode  string            // "keep-id" for rootless
	Stdout      io.Writer
	Stderr      io.Writer
	Stdin       io.Reader
	Remove      bool // auto-remove after exit
}

// Mount describes a bind mount.
type Mount struct {
	Source   string
	Target  string
	ReadOnly bool
	Options []string // e.g. "U" for podman UID mapping, "noexec", "nosuid"
}

// New creates an Engine connected to the container runtime.
// It auto-detects the socket path unless $CONTAINER_HOST is set.
func New() (Engine, error) {
	addr, err := detectSocket()
	if err != nil {
		return nil, fmt.Errorf("container engine: %w", err)
	}
	client := newHTTPClient(addr)
	return &podmanEngine{client: client, base: apiBase(addr)}, nil
}

// NewFromAddress creates an Engine connected to a specific address.
// Supports "unix:///path/to/socket" and "tcp://host:port".
func NewFromAddress(addr string) (Engine, error) {
	client := newHTTPClient(addr)
	return &podmanEngine{client: client, base: apiBase(addr)}, nil
}

func detectSocket() (string, error) {
	// 1. Explicit override
	if host := os.Getenv("CONTAINER_HOST"); host != "" {
		return host, nil
	}

	// 2. Standard rootless socket
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		sock := filepath.Join(xdg, "podman", "podman.sock")
		if _, err := os.Stat(sock); err == nil {
			return "unix://" + sock, nil
		}
	}

	// 3. Fallback rootless socket
	uid := strconv.Itoa(os.Getuid())
	sock := filepath.Join("/run/user", uid, "podman", "podman.sock")
	if _, err := os.Stat(sock); err == nil {
		return "unix://" + sock, nil
	}

	// 4. Rootful socket
	sock = "/run/podman/podman.sock"
	if _, err := os.Stat(sock); err == nil {
		return "unix://" + sock, nil
	}

	return "", fmt.Errorf(
		"no container engine socket found; set $CONTAINER_HOST or " +
			"enable the podman socket: systemctl --user enable --now podman.socket")
}
