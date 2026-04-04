// Package container provides a thin client for container engine REST APIs.
// All container and external operations go through this interface,
// eliminating os/exec as an attack vector entirely.
package container

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

	// TLSIdentity returns the TLS certificate fingerprints captured from the
	// engine connection. Returns nil for Unix socket connections.
	TLSIdentity() *TLSIdentity

	// Identity returns the engine's combined transport and runtime identity.
	// Populated after Ping (transport) and Info (runtime). Returns non-nil
	// even if Info fails -- the connection info is always available after Ping.
	Identity() *EngineIdentity

	// Info fetches runtime metadata from the engine. Call after Ping.
	// Failures are non-fatal: Identity().Runtime will be nil.
	Info(ctx context.Context) error
}

// ImageInfo holds metadata from image inspection.
type ImageInfo struct {
	Annotations map[string]string
	ID          string
	Digest      string
	RepoDigests []string
	Size        int64
}

// RunOpts configures a container execution.
type RunOpts struct {
	Stdin       io.Reader
	Stderr      io.Writer
	Stdout      io.Writer
	Env         map[string]string
	Tmpfs       map[string]string
	Image       string
	Network     string
	UsernsMode  string
	Mounts      []Mount
	SecurityOpt []string
	CapDrop     []string
	Cmd         []string
	ReadOnly    bool
	Remove      bool
}

// Mount describes a bind mount.
type Mount struct {
	Source   string
	Target   string
	Options  []string
	ReadOnly bool
}

// DefaultSecureOpts returns a RunOpts with the standard hardened security
// profile. Callers override specific fields (Image, Cmd, Network, Mounts).
func DefaultSecureOpts() RunOpts {
	return RunOpts{
		CapDrop:     []string{"ALL"},
		ReadOnly:    true,
		SecurityOpt: []string{"no-new-privileges"},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=512m"},
		UsernsMode:  "keep-id",
		Remove:      true,
	}
}

// EngineIdentity holds everything strike knows about the container engine
// it is connected to. Populated after Ping and Info calls. Embedded in
// deploy attestations for supply chain traceability.
type EngineIdentity struct {
	// Runtime describes the engine's self-reported properties.
	// Populated from the /info API. Nil if the call failed.
	Runtime *RuntimeInfo `json:"runtime,omitempty"`

	// Connection describes how strike connects to the engine.
	Connection ConnectionInfo `json:"connection"`
}

// ConnectionInfo describes the transport between strike and the engine.
type ConnectionInfo struct {
	// Type is "unix", "tls", or "mtls".
	Type string `json:"type"`

	// CATrustMode is "pinned" if an explicit CA was configured, or "system"
	// if the OS trust store was used. Empty for Unix socket connections.
	// Verifiers use this to assess the scope of trust behind the server
	// certificate fingerprint.
	CATrustMode string `json:"ca_trust_mode,omitempty"`

	// ServerCertFingerprint is the SHA-256 of the engine's leaf certificate.
	// Empty for Unix socket connections.
	ServerCertFingerprint string `json:"server_cert_fingerprint,omitempty"`

	// ServerCertSubject is the Subject CN of the engine's certificate.
	ServerCertSubject string `json:"server_cert_subject,omitempty"`

	// ServerCertIssuer is the Issuer CN of the engine's certificate.
	ServerCertIssuer string `json:"server_cert_issuer,omitempty"`

	// ClientCertFingerprint is the SHA-256 of the controller's certificate.
	// Empty unless mTLS is configured.
	ClientCertFingerprint string `json:"client_cert_fingerprint,omitempty"`

	// ClientCertSubject is the Subject CN of the controller's certificate.
	ClientCertSubject string `json:"client_cert_subject,omitempty"`
}

// RuntimeInfo holds the engine's self-reported metadata from /info.
type RuntimeInfo struct {
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
	Rootless   bool   `json:"rootless"`
	SELinux    bool   `json:"selinux"`
	AppArmor   bool   `json:"apparmor"`
}

// New creates an Engine connected to the container runtime.
// It auto-detects the socket path unless $CONTAINER_HOST is set.
func New() (Engine, error) {
	addr, err := detectSocket()
	if err != nil {
		return nil, fmt.Errorf("container engine: %w", err)
	}
	return NewFromAddress(addr)
}

// NewFromAddress creates an Engine connected to a specific address.
// Supports "unix:///path/to/socket" and "tcp://host:port".
func NewFromAddress(addr string) (Engine, error) {
	tlsCfg := LoadTLSConfig()
	client, err := newHTTPClient(addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("container engine %s: %w", addr, err)
	}
	return &podmanEngine{
		client: client,
		base:   apiBase(addr),
		tlsCfg: tlsCfg,
		isUnix: strings.HasPrefix(addr, "unix://"),
	}, nil
}

func detectSocket() (string, error) {
	// 1. Explicit override
	if host := os.Getenv("CONTAINER_HOST"); host != "" {
		return host, nil
	}

	// 2. Standard rootless socket
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		sock := filepath.Join(xdg, "podman", "podman.sock")
		if _, err := os.Stat(sock); err == nil { //nolint:gosec // G703: socket path from known locations or $CONTAINER_HOST
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
