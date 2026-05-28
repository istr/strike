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

	"github.com/istr/strike/internal/probe"
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

	// ImageSave exports an image as an OCI archive tar.
	ImageSave(ctx context.Context, tag string) (io.ReadCloser, error)

	// ContainerRun creates, starts, waits for, and removes a container.
	// Stdout and stderr are streamed to the provided writers.
	// Returns the exit code.
	ContainerRun(ctx context.Context, opts RunOpts) (int, error)

	// ContainerRunHeld creates, optionally seeds, starts, streams logs from,
	// and waits for a container but does NOT remove it. Seeds are tar streams
	// the engine extracts into the container before start (ADR-036 input
	// delivery); pass nil for none. Auto-removal is forced off so the stopped
	// container survives for extraction. Returns the container id (valid for
	// cleanup even on a post-create error) and the exit code. The caller owns
	// removal (ContainerRemove) and extraction (ContainerArchive).
	ContainerRunHeld(ctx context.Context, opts RunOpts, seeds []Seed) (string, int, error)

	// ContainerArchive returns a tar stream of path from the container's
	// filesystem. The container may be stopped. The caller must close the
	// returned reader.
	ContainerArchive(ctx context.Context, id, path string) (io.ReadCloser, error)

	// ContainerRemove force-removes a container by id.
	ContainerRemove(ctx context.Context, id string) error

	// VolumeCreate creates a named engine-managed volume.
	VolumeCreate(ctx context.Context, name string) error

	// SeedVolumes populates one or more named volumes in a single batch.
	// Internally creates a throwaway helper container (never started) with
	// all volumes mounted, PUTs each tar via the container archive endpoint,
	// then removes the helper. The volumes must already exist. A minimal
	// scratch image is imported on first call and reused thereafter.
	SeedVolumes(ctx context.Context, seeds []VolumeSeed) error

	// VolumeRemove removes a named engine-managed volume.
	VolumeRemove(ctx context.Context, name string) error

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
	Stdin        io.Reader
	Stderr       io.Writer
	Stdout       io.Writer
	Env          map[string]string
	Tmpfs        map[string]string
	Image        string
	Network      string
	UsernsMode   string
	Workdir      string
	Mounts       []Mount
	ImageVolumes []ImageVolume
	TrustVolumes []VolumeMount
	Volume       *VolumeMount
	SecurityOpt  []string
	CapDrop      []string
	Cmd          []string
	Entrypoint   []string
	PastaArgs    []string // pasta options when Network == "pasta"
	DNSServers   []string // resolv.conf nameservers in the container
	ReadOnly     bool
	Remove       bool
}

// Mount describes a bind mount.
type Mount struct {
	Source   string
	Target   string
	Options  []string
	ReadOnly bool
}

// Seed is content delivered into a created-but-not-started container
// before it starts. Tar is a tar stream the engine extracts at Path inside
// the container (typically a writable named volume mounted there). It carries
// step inputs into the workdir volume without host materialization (ADR-036
// seed delivery). Pass a length-known reader (e.g. *bytes.Reader) so the
// request carries Content-Length.
type Seed struct {
	Tar  io.Reader
	Path string
}

// VolumeSeed pairs a named volume with a tar stream to extract into it.
// Used by SeedVolumes to batch-populate volumes before any step runs.
type VolumeSeed struct {
	Tar    io.Reader
	Volume string
}

// VolumeMount describes the named engine-managed volume mounted into the
// container as its single writable surface (the workdir), required under
// the read-only root profile. Unlike Mount (a host bind), the source is an
// engine volume, so no host path is involved.
type VolumeMount struct {
	Name    string
	Dest    string
	Options []string
}

// ImageVolume describes a read-only mount whose source is an existing
// engine image rather than a host path or a named volume. Source is the
// producer image tag (a local WrapTag); Destination is the mount path in
// the container; SubPath selects a directory within the image content
// (directory-granular -- a SubPath resolving to a regular file is rejected
// by the OCI runtime at start, so callers reject single-file selections
// before constructing one). ReadWrite is carried explicitly and stays
// false for input delivery: an input must never be silently writable
// (ADR-036 outside-workdir delivery).
type ImageVolume struct {
	Source      string
	Destination string
	SubPath     string
	ReadWrite   bool
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
		if _, err := probe.Stat(sock); err == nil {
			return "unix://" + sock, nil
		}
	}

	// 3. Fallback rootless socket
	uid := strconv.Itoa(os.Getuid())
	sock := filepath.Join("/run/user", uid, "podman", "podman.sock")
	if _, err := probe.Stat(sock); err == nil {
		return "unix://" + sock, nil
	}

	// 4. Rootful socket
	sock = "/run/podman/podman.sock"
	if _, err := probe.Stat(sock); err == nil {
		return "unix://" + sock, nil
	}

	return "", fmt.Errorf(
		"no container engine socket found; set $CONTAINER_HOST or " +
			"enable the podman socket: systemctl --user enable --now podman.socket")
}
