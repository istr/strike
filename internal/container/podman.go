package container

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
)

type podmanEngine struct {
	client   *http.Client
	tlsCfg   TLSConfig
	tlsID    *TLSIdentity
	identity *EngineIdentity
	base     string
	isUnix   bool
}

// TLSIdentity returns the TLS certificate fingerprints captured from the
// engine connection. Returns nil for Unix socket connections.
func (e *podmanEngine) TLSIdentity() *TLSIdentity {
	return e.tlsID
}

// Identity returns the engine's combined transport and runtime identity.
func (e *podmanEngine) Identity() *EngineIdentity {
	return e.identity
}

// Ping verifies the engine is reachable.
func (e *podmanEngine) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.base+"/_ping", nil)
	if err != nil {
		return err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("engine ping: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN close response body: %v", err)
		}
	}()

	e.captureTLSIdentity(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("engine ping: status %d", resp.StatusCode)
	}
	return nil
}

// captureTLSIdentity extracts certificate fingerprints from the TLS
// connection state. Called once after the first successful API call.
func (e *podmanEngine) captureTLSIdentity(resp *http.Response) {
	if e.identity != nil {
		return // already captured
	}

	e.identity = &EngineIdentity{}

	if e.isUnix {
		e.identity.Connection.Type = endpoint.EngineTypeUnix
		return
	}

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		e.identity.Connection.Type = endpoint.EngineTypeTls
		return
	}

	serverCert := resp.TLS.PeerCertificates[0]
	e.identity.Connection.ServerCertFingerprint = CertFingerprint(serverCert)
	e.identity.Connection.ServerCertSubject = serverCert.Subject.CommonName
	e.identity.Connection.ServerCertIssuer = serverCert.Issuer.CommonName

	if e.tlsCfg.HasClientCert() {
		e.identity.Connection.Type = endpoint.EngineTypeMtls
		clientPair, loadErr := tls.LoadX509KeyPair(e.tlsCfg.CertFile, e.tlsCfg.KeyFile)
		if loadErr == nil && len(clientPair.Certificate) > 0 {
			clientCert, parseErr := x509.ParseCertificate(clientPair.Certificate[0])
			if parseErr == nil {
				e.identity.Connection.ClientCertFingerprint = CertFingerprint(clientCert)
				e.identity.Connection.ClientCertSubject = clientCert.Subject.CommonName
			}
		}
	} else {
		e.identity.Connection.Type = endpoint.EngineTypeTls
	}

	if e.tlsCfg.IsPinned() {
		e.identity.Connection.CATrustType = endpoint.CATrustTypePinned
	} else {
		e.identity.Connection.CATrustType = endpoint.CATrustTypeSystem
	}

	e.tlsID = &TLSIdentity{
		ServerFingerprint: e.identity.Connection.ServerCertFingerprint,
		ServerSubject:     e.identity.Connection.ServerCertSubject,
		ServerIssuer:      e.identity.Connection.ServerCertIssuer,
		ClientFingerprint: e.identity.Connection.ClientCertFingerprint,
		ClientSubject:     e.identity.Connection.ClientCertSubject,
		Mutual:            e.identity.Connection.Type == endpoint.EngineTypeMtls,
	}
}

// Info fetches runtime metadata from the engine.
func (e *podmanEngine) Info(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.base+"/info", nil)
	if err != nil {
		return err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("engine info: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN close response body: %v", err)
		}
	}()

	var raw struct {
		Version struct {
			Version    string `json:"Version"`
			APIVersion string `json:"APIVersion"`
		} `json:"version"`
		Host struct {
			Security struct {
				SELinuxEnabled  bool `json:"selinuxEnabled"`
				AppArmorEnabled bool `json:"apparmorEnabled"`
				Rootless        bool `json:"rootless"`
			} `json:"security"`
		} `json:"host"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return fmt.Errorf("engine info: decode: %w", err)
	}

	if e.identity == nil {
		e.identity = &EngineIdentity{}
	}
	e.identity.Runtime = &RuntimeInfo{
		Version:    raw.Version.Version,
		APIVersion: raw.Version.APIVersion,
		Rootless:   raw.Host.Security.Rootless,
		SELinux:    raw.Host.Security.SELinuxEnabled,
		AppArmor:   raw.Host.Security.AppArmorEnabled,
	}
	return nil
}

// ImageExists checks if an image exists in the local store.
func (e *podmanEngine) ImageExists(ctx context.Context, ref string) (bool, error) {
	u := e.base + "/images/" + url.PathEscape(ref) + "/exists"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN close response body: %v", err)
		}
	}()
	return resp.StatusCode == http.StatusNoContent, nil
}

// ImagePull fetches an image from a remote registry.
func (e *podmanEngine) ImagePull(ctx context.Context, ref string) error {
	u := e.base + "/images/pull?reference=" + url.QueryEscape(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("image pull %s: %w", ref, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN close response body: %v", err)
		}
	}()
	// The pull response is a stream of JSON objects. Read to completion.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("image pull %s: read response: %w", ref, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("image pull %s: status %d", ref, resp.StatusCode)
	}
	return nil
}

// ImagePush pushes a local image to a remote registry.
func (e *podmanEngine) ImagePush(ctx context.Context, name string) error {
	u := e.base + "/images/" + url.PathEscape(name) + "/push"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	// Auth from default keychain (podman uses $XDG_RUNTIME_DIR/containers/auth.json).
	// Base64 of "{}" signals "use default credentials".
	req.Header.Set("X-Registry-Auth", "e30=")
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("image push %s: %w", name, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN close response body: %v", err)
		}
	}()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("image push %s: status %d", name, resp.StatusCode)
	}
	return nil
}

// ImageLoad loads an OCI tar archive into the local store.
func (e *podmanEngine) ImageLoad(ctx context.Context, input io.Reader) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/images/load", input)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("image load: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close response body: %v", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("image load: read response: %w", err)
	}

	// Podman native: {"Names": ["sha256:..."]}
	var native struct {
		Names []string `json:"Names"`
	}
	if json.Unmarshal(body, &native) == nil && len(native.Names) > 0 {
		return native.Names[0], nil
	}

	// Compat (Docker-style): {"stream": "Loaded image: sha256:abc123\n"}
	var compat struct {
		Stream string `json:"stream"`
	}
	if json.Unmarshal(body, &compat) == nil && compat.Stream != "" {
		return parseLoadedImageID(compat.Stream), nil
	}

	return "", fmt.Errorf("image load: unexpected response: %s", body)
}

// parseLoadedImageID extracts the image ID from a Docker-style load response.
func parseLoadedImageID(stream string) string {
	// "Loaded image: sha256:abc123\n" or "Loaded image(s): sha256:abc123\n"
	stream = strings.TrimSpace(stream)
	if idx := strings.LastIndex(stream, ": "); idx >= 0 {
		return strings.TrimSpace(stream[idx+2:])
	}
	return stream
}

// ImageInspect returns metadata for a local image.
func (e *podmanEngine) ImageInspect(ctx context.Context, ref string) (*ImageInfo, error) {
	u := e.base + "/images/" + url.PathEscape(ref) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("image inspect %s: %w", ref, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN close response body: %v", err)
		}
	}()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("image %s not found", ref)
	}
	// Libpod inspect response
	var raw struct {
		Annotations map[string]string `json:"Annotations"`
		ID          string            `json:"Id"`
		Digest      string            `json:"Digest"`
		RepoDigests []string          `json:"RepoDigests"`
		Size        int64             `json:"Size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("image inspect %s: decode: %w", ref, err)
	}
	return &ImageInfo{
		ID:          raw.ID,
		Digest:      primitive.Digest(raw.Digest),
		RepoDigests: raw.RepoDigests,
		Annotations: raw.Annotations,
		Size:        raw.Size,
	}, nil
}

// ImageTag adds a tag to an existing image.
func (e *podmanEngine) ImageTag(ctx context.Context, source, target string) error {
	// Parse target into repo and tag
	repo, tag := parseImageRef(target)
	u := e.base + "/images/" + url.PathEscape(source) + "/tag" +
		"?repo=" + url.QueryEscape(repo) + "&tag=" + url.QueryEscape(tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("image tag %s -> %s: %w", source, target, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN close response body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("image tag: status %d", resp.StatusCode)
	}
	return nil
}

// ImageSave exports an image as an OCI archive tar via GET /images/<tag>/get.
func (e *podmanEngine) ImageSave(ctx context.Context, tag string) (io.ReadCloser, error) {
	u := e.base + "/images/" + url.PathEscape(tag) + "/get"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("image save %s: %w", tag, err)
	}
	if resp.StatusCode != http.StatusOK {
		closer.Warn(resp.Body, "image save")
		return nil, fmt.Errorf("image save %s: status %d", tag, resp.StatusCode)
	}
	return resp.Body, nil
}

// runContainer creates, optionally seeds, starts, streams logs from, and
// waits for a container. It does not remove the container. It returns the
// container id (valid for cleanup even when a post-create step errors) and
// the exit code. ContainerRun and ContainerRunHeld share this body.
func (e *podmanEngine) runContainer(ctx context.Context, opts RunOpts, seeds []Seed) (string, int, error) {
	id, err := e.containerCreate(ctx, opts)
	if err != nil {
		return "", -1, fmt.Errorf("container create: %w", err)
	}
	// Seed input content into the created (not yet started) container's
	// writable volume before start. The container has not run, so nothing
	// observes a partial seed; a failed PUT aborts before start with the id
	// returned for cleanup. See ADR-036 seed delivery.
	for _, s := range seeds {
		if putErr := e.containerArchivePut(ctx, id, s.Path, s.Tar); putErr != nil {
			return id, -1, fmt.Errorf("container seed %q: %w", s.Path, putErr)
		}
	}
	if startErr := e.containerStart(ctx, id); startErr != nil {
		return id, -1, fmt.Errorf("container start: %w", startErr)
	}
	done := make(chan error, 1)
	go func() {
		done <- e.containerLogs(ctx, id, opts.Stdout, opts.Stderr)
	}()
	exitCode, err := e.containerWait(ctx, id)
	if err != nil {
		return id, -1, fmt.Errorf("container wait: %w", err)
	}
	if logErr := <-done; logErr != nil {
		log.Printf("WARN log streaming: %v", logErr)
	}
	return id, exitCode, nil
}

// ContainerRun creates, starts, waits for, and removes a container.
func (e *podmanEngine) ContainerRun(ctx context.Context, opts RunOpts) (int, error) {
	id, exitCode, err := e.runContainer(ctx, opts, nil)
	if err != nil {
		return exitCode, err
	}
	if opts.Remove {
		if rmErr := e.containerRemove(ctx, id); rmErr != nil {
			return exitCode, fmt.Errorf("container remove: %w", rmErr)
		}
	}
	return exitCode, nil
}

// ContainerRunHeld runs the container without removing it, returning its id.
// Auto-removal is forced off (overriding opts.Remove) so the stopped
// container survives for extraction by the caller. seeds are extracted into
// the container before start (ADR-036 input delivery); pass nil for none.
func (e *podmanEngine) ContainerRunHeld(ctx context.Context, opts RunOpts, seeds []Seed) (string, int, error) {
	opts.Remove = false
	return e.runContainer(ctx, opts, seeds)
}

// ContainerRemove force-removes a container by id.
func (e *podmanEngine) ContainerRemove(ctx context.Context, id string) error {
	return e.containerRemove(ctx, id)
}

func (e *podmanEngine) containerCreate(ctx context.Context, opts RunOpts) (string, error) {
	spec := buildSpecGenerator(opts)
	body, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.base+"/containers/create", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN close response body: %v", err)
		}
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", fmt.Errorf("container create: status %d: (body read failed)", resp.StatusCode)
		}
		return "", fmt.Errorf("container create: status %d: %s", resp.StatusCode, body)
	}
	var result struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.ID == "" {
		return "", fmt.Errorf("container create: engine returned empty container id")
	}
	return result.ID, nil
}

func (e *podmanEngine) containerStart(ctx context.Context, id string) error {
	u := e.base + "/containers/" + id + "/start"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN close response body: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusNoContent {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("start: status %d: (body read failed)", resp.StatusCode)
		}
		return fmt.Errorf("start: status %d: %s", resp.StatusCode, body)
	}
	return nil
}

func (e *podmanEngine) containerWait(ctx context.Context, id string) (int, error) {
	u := e.base + "/containers/" + id + "/wait"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return -1, err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return -1, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close response body: %v", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return -1, err
	}

	// Podman native API returns {"Error":...,"StatusCode":N}.
	// Podman compat API may return just the integer exit code.
	var result struct {
		Error *struct {
			Message string
		} `json:"Error"`
		StatusCode int `json:"StatusCode"`
	}
	if json.Unmarshal(body, &result) == nil {
		if result.Error != nil && result.Error.Message != "" {
			return result.StatusCode, fmt.Errorf("wait: %s", result.Error.Message)
		}
		return result.StatusCode, nil
	}

	// Fallback: bare integer (compat endpoint).
	var exitCode int
	if json.Unmarshal(body, &exitCode) == nil {
		return exitCode, nil
	}

	return -1, fmt.Errorf("unexpected wait response: %s", body)
}

func (e *podmanEngine) containerLogs(ctx context.Context, id string, stdout, stderr io.Writer) error {
	u := e.base + "/containers/" + id + "/logs?follow=true&stdout=true&stderr=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN close response body: %v", err)
		}
	}()
	// Libpod log stream: each frame has an 8-byte header (stream type + size),
	// followed by the payload. Stream type: 0=stdin, 1=stdout, 2=stderr.
	return demuxLogStream(resp.Body, stdout, stderr)
}

func (e *podmanEngine) containerRemove(ctx context.Context, id string) error {
	u := e.base + "/containers/" + id + "?force=true&v=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN close response body: %v", err)
		}
	}()
	return nil
}

// ContainerArchive returns a tar stream of path from the container's
// filesystem. The caller must close the returned reader.
func (e *podmanEngine) ContainerArchive(ctx context.Context, id, path string) (io.ReadCloser, error) {
	// VERIFY AGAINST LIVE ENGINE -- confirmed podman 5.4.2: libpod GET
	// /containers/{id}/archive?path= returns a tar archive of path.
	// Succeeds on a stopped container; query parameter is "path".
	u := e.base + "/containers/" + id + "/archive?path=" + url.QueryEscape(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("container archive %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close response body: %v", closeErr)
		}
		if readErr != nil {
			return nil, fmt.Errorf("container archive %s: status %d: (body read failed)", path, resp.StatusCode)
		}
		return nil, fmt.Errorf("container archive %s: status %d: %s", path, resp.StatusCode, body)
	}
	return resp.Body, nil
}

func (e *podmanEngine) ContainerCommit(ctx context.Context, id string) (string, error) {
	u := e.base + "/commit?container=" + url.QueryEscape(id) + "&pause=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("container commit %s: %w", id, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close response body: %v", closeErr)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("container commit %s: read response: %w", id, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("container commit %s: status %d: %s", id, resp.StatusCode, body)
	}
	var result struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("container commit %s: unmarshal: %w", id, err)
	}
	return result.ID, nil
}

// containerArchivePut extracts a tar stream into dstPath inside a container.
// It succeeds on a created-but-not-started container, which is how step
// inputs are seeded into the writable workdir volume before start.
func (e *podmanEngine) containerArchivePut(ctx context.Context, id, dstPath string, tar io.Reader) error {
	// VERIFY AGAINST LIVE ENGINE -- confirmed podman 5.4.2: libpod PUT
	// /containers/{id}/archive?path= extracts a tar into path and returns
	// 200. Succeeds on a created (not started) container; query param "path".
	u := e.base + "/containers/" + id + "/archive?path=" + url.QueryEscape(dstPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, tar)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("container archive put %s: %w", dstPath, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("container archive put %s: status %d: (body read failed)", dstPath, resp.StatusCode)
		}
		return fmt.Errorf("container archive put %s: status %d: %s", dstPath, resp.StatusCode, body)
	}
	return nil
}

// VolumeCreate creates a named engine-managed volume.
func (e *podmanEngine) VolumeCreate(ctx context.Context, name string) error {
	// VERIFY AGAINST LIVE ENGINE -- confirmed podman 5.4.2: libpod POST
	// /volumes/create with body {"Name":"..."} returns 201 and the volume
	// JSON. Body key casing is "Name"; success status is 201.
	body, err := json.Marshal(map[string]string{"Name": name})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.base+"/volumes/create", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("volume create %s: %w", name, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusCreated {
		b, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("volume create %s: status %d: (body read failed)", name, resp.StatusCode)
		}
		return fmt.Errorf("volume create %s: status %d: %s", name, resp.StatusCode, b)
	}
	return nil
}

// seedScratchRef is the local tag for the minimal scratch image used by
// SeedVolumes as the helper container's base. Imported once (empty tar)
// and reused for all subsequent seed operations.
const seedScratchRef = "localhost/strike-seed-scratch:latest"

// ensureSeedImage imports a minimal scratch image if it does not already
// exist. The image is an empty tar (1024 null bytes); the container
// created from it is never started -- it only serves as a mount carrier
// for the archive PUT that populates volumes.
func (e *podmanEngine) ensureSeedImage(ctx context.Context) error {
	ok, err := e.ImageExists(ctx, seedScratchRef)
	if err != nil {
		return fmt.Errorf("seed image check: %w", err)
	}
	if ok {
		return nil
	}
	t, tErr := emptyTar()
	if tErr != nil {
		return fmt.Errorf("seed scratch tar: %w", tErr)
	}
	return e.imageImport(ctx, t, seedScratchRef)
}

// emptyTar returns a valid empty tar archive (two 512-byte zero blocks).
func emptyTar() (io.Reader, error) {
	var buf bytes.Buffer
	if err := tar.NewWriter(&buf).Close(); err != nil {
		return nil, err
	}
	return &buf, nil
}

// imageImport imports a tar stream as an image with the given reference.
func (e *podmanEngine) imageImport(ctx context.Context, tarStream io.Reader, ref string) error {
	u := e.base + "/images/import?reference=" + url.QueryEscape(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, tarStream)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("image import %s: %w", ref, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		b, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("image import %s: status %d: (body read failed)", ref, resp.StatusCode)
		}
		return fmt.Errorf("image import %s: status %d: %s", ref, resp.StatusCode, b)
	}
	return nil
}

// SeedVolumes populates one or more named volumes in a single batch.
// A throwaway helper container mounts all volumes at /seed/0../seed/N;
// each tar is extracted via archive PUT. The helper is never started and
// removed after all PUTs complete. Volumes must already exist.
func (e *podmanEngine) SeedVolumes(ctx context.Context, seeds []VolumeSeed) error {
	if len(seeds) == 0 {
		return nil
	}
	if err := e.ensureSeedImage(ctx); err != nil {
		return err
	}

	vols := make([]specNamedVolume, len(seeds))
	dests := make([]string, len(seeds))
	for i, sd := range seeds {
		dests[i] = fmt.Sprintf("/seed/%d", i)
		vols[i] = specNamedVolume{Name: sd.Volume, Dest: dests[i]}
	}

	id, createErr := e.seedContainerCreate(ctx, vols)
	if createErr != nil {
		return fmt.Errorf("seed helper create: %w", createErr)
	}
	defer func() {
		if rmErr := e.containerRemove(ctx, id); rmErr != nil {
			log.Printf("WARN seed helper remove: %v", rmErr)
		}
	}()

	for i, sd := range seeds {
		if err := e.containerArchivePut(ctx, id, dests[i], sd.Tar); err != nil {
			return fmt.Errorf("seed volume %s: %w", sd.Volume, err)
		}
	}
	return nil
}

// seedContainerCreate creates a never-started helper container from the
// scratch image with the given named volume mounts.
func (e *podmanEngine) seedContainerCreate(ctx context.Context, vols []specNamedVolume) (string, error) {
	spec := map[string]any{
		"image":   seedScratchRef,
		"volumes": vols,
	}
	body, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.base+"/containers/create", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusCreated {
		b, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", fmt.Errorf("status %d: (body read failed)", resp.StatusCode)
		}
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, b)
	}
	var result struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.ID, nil
}

// VolumeRemove removes a named engine-managed volume.
func (e *podmanEngine) VolumeRemove(ctx context.Context, name string) error {
	// VERIFY AGAINST LIVE ENGINE -- confirmed podman 5.4.2: libpod DELETE
	// /volumes/{name}?force=true returns 204. Force is accepted.
	u := e.base + "/volumes/" + url.PathEscape(name) + "?force=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("volume remove %s: %w", name, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close response body: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusNoContent {
		b, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("volume remove %s: status %d: (body read failed)", name, resp.StatusCode)
		}
		return fmt.Errorf("volume remove %s: status %d: %s", name, resp.StatusCode, b)
	}
	return nil
}

// specGen is the libpod SpecGenerator wire payload for container create.
// The json tags are the version-pinned wire contract: key names and casing
// matter and are non-uniform across nested types (the OCI runtime Mount is
// lowercase; the podman NamedVolume is PascalCase). Conditional inclusion is
// expressed by omitempty/pointer fields, not by builder branching. image,
// command, and remove are emitted unconditionally (no omitempty); remove must
// carry false so ContainerRunHeld suppresses engine auto-removal.
// VERIFY AGAINST LIVE ENGINE -- confirmed podman 5.4.2.
type specGen struct {
	Env                map[string]string   `json:"env,omitempty"`
	Netns              *specNamespace      `json:"netns,omitempty"`
	Userns             *specNamespace      `json:"userns,omitempty"`
	NetworkOptions     *specNetworkOptions `json:"network_options,omitempty"`
	Image              string              `json:"image"`
	WorkDir            string              `json:"work_dir,omitempty"`
	Command            []string            `json:"command"`
	Entrypoint         []string            `json:"entrypoint,omitempty"`
	Mounts             []specMount         `json:"mounts,omitempty"`
	Volumes            []specNamedVolume   `json:"volumes,omitempty"`
	ImageVolumes       []specImageVolume   `json:"image_volumes,omitempty"`
	DNSServer          []string            `json:"dns_server,omitempty"`
	CapDrop            []string            `json:"cap_drop,omitempty"`
	SecurityOpt        []string            `json:"security_opt,omitempty"`
	ReadOnlyFilesystem bool                `json:"read_only_filesystem,omitempty"`
	Remove             bool                `json:"remove"`
}

// specNamespace is a libpod netns/userns entry: {"nsmode": "..."}.
type specNamespace struct {
	NSMode string `json:"nsmode"`
}

// specNetworkOptions carries per-backend network options. Only pasta is wired
// today: {"pasta": [...]}.
type specNetworkOptions struct {
	Pasta []string `json:"pasta,omitempty"`
}

// specMount is one entry of the SpecGenerator "mounts" array, following the
// OCI runtime Mount spec (lowercase keys). A bind entry carries Source and
// type "bind"; a tmpfs entry omits Source and carries type "tmpfs".
type specMount struct {
	Destination string   `json:"destination"`
	Source      string   `json:"source,omitempty"`
	Type        string   `json:"type"`
	Options     []string `json:"options,omitempty"`
}

// specNamedVolume is one entry of the SpecGenerator "volumes" array, the
// podman NamedVolume struct (PascalCase keys).
type specNamedVolume struct {
	Name    string   `json:"Name"`
	Dest    string   `json:"Dest"`
	Options []string `json:"Options,omitempty"`
}

// specImageVolume is one entry of the SpecGenerator "image_volumes" array,
// the podman ImageVolume struct (PascalCase keys). ReadWrite is emitted
// without omitempty so a read-only input cannot be silently promoted to
// writable by a dropped false; SubPath is optional (empty selects the
// image content root).
// VERIFY AGAINST LIVE ENGINE -- confirmed podman 5.4.2: a read-only entry
// is {Source, Destination, ReadWrite, SubPath}; SubPath is directory-only.
type specImageVolume struct {
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	SubPath     string `json:"SubPath,omitempty"`
	ReadWrite   bool   `json:"ReadWrite"`
}

// buildSpecGenerator constructs the libpod SpecGenerator wire payload from
// RunOpts. Empty/zero fields are dropped by the omitempty tags on specGen;
// the only branches that remain are the ones that must avoid a nil
// dereference (Volume) or that populate a typed sub-object only under a
// semantic condition (netns/userns/network_options).
func buildSpecGenerator(opts RunOpts) specGen {
	spec := specGen{
		Image:              string(opts.Image),
		Command:            opts.Cmd,
		Entrypoint:         opts.Entrypoint,
		WorkDir:            opts.Workdir,
		Env:                opts.Env,
		Mounts:             buildMounts(opts),
		DNSServer:          opts.DNSServers,
		CapDrop:            opts.CapDrop,
		SecurityOpt:        opts.SecurityOpt,
		ReadOnlyFilesystem: opts.ReadOnly,
		Remove:             opts.Remove,
	}

	// Named volumes: the writable workdir surface (opts.Volume) plus any
	// read-only trust-material volumes (opts.TrustVolumes, e.g. the
	// lane-wide CA volume masking /etc/ssl/certs).
	if opts.Volume != nil || len(opts.TrustVolumes) > 0 {
		spec.Volumes = buildVolumes(opts)
	}

	// Read-only image volumes (engine-native inputs mounted outside the
	// workdir, ADR-036). Each references a producer image tag as Source.
	if len(opts.ImageVolumes) > 0 {
		spec.ImageVolumes = buildImageVolumes(opts)
	}

	// Network
	if opts.Network != "" {
		spec.Netns = &specNamespace{NSMode: opts.Network}
		if opts.Network == "pasta" && len(opts.PastaArgs) > 0 {
			spec.NetworkOptions = &specNetworkOptions{Pasta: opts.PastaArgs}
		}
	}

	// User namespace
	if opts.UsernsMode != "" {
		spec.Userns = &specNamespace{NSMode: opts.UsernsMode}
	}

	return spec
}

func buildMounts(opts RunOpts) []specMount {
	var mounts []specMount
	for _, m := range opts.Mounts {
		mount := specMount{
			Destination: m.Target,
			Source:      m.Source,
			Type:        "bind",
		}
		mountOpts := append([]string{}, m.Options...)
		if m.ReadOnly {
			mountOpts = append(mountOpts, "ro")
		}
		if len(mountOpts) > 0 {
			mount.Options = mountOpts
		}
		mounts = append(mounts, mount)
	}
	for path, options := range opts.Tmpfs {
		mounts = append(mounts, specMount{
			Destination: path,
			Type:        "tmpfs",
			Options:     strings.Split(options, ","),
		})
	}
	return mounts
}

// buildVolumes maps the writable workdir volume and any read-only trust
// volumes into the libpod SpecGenerator "volumes" array.
func buildVolumes(opts RunOpts) []specNamedVolume {
	// VERIFY AGAINST LIVE ENGINE -- confirmed podman 5.4.2: the libpod
	// SpecGenerator names this key "volumes", with entries
	// {"Name","Dest","Options"}.
	var out []specNamedVolume
	if opts.Volume != nil {
		v := opts.Volume
		entry := specNamedVolume{Name: v.Name, Dest: v.Dest}
		if len(v.Options) > 0 {
			entry.Options = v.Options
		}
		out = append(out, entry)
	}
	for _, tv := range opts.TrustVolumes {
		entry := specNamedVolume{Name: tv.Name, Dest: tv.Dest}
		entry.Options = append(append([]string{}, tv.Options...), "ro")
		out = append(out, entry)
	}
	return out
}

// buildImageVolumes maps the read-only image-volume inputs into the libpod
// SpecGenerator "image_volumes" array. ReadWrite is copied through (always
// false for input delivery) and emitted explicitly, so an input can never
// be silently writable.
func buildImageVolumes(opts RunOpts) []specImageVolume {
	out := make([]specImageVolume, len(opts.ImageVolumes))
	for i, iv := range opts.ImageVolumes {
		out[i] = specImageVolume(iv)
	}
	return out
}

// demuxLogStream reads the Docker/libpod multiplexed log stream.
// Each frame: [stream_type(1)][0(3)][size(4 big-endian)][payload(size)].
func demuxLogStream(r io.Reader, stdout, stderr io.Writer) error {
	header := make([]byte, 8)
	for {
		_, err := io.ReadFull(r, header)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		size := int(header[4])<<24 | int(header[5])<<16 | int(header[6])<<8 | int(header[7])
		var dst io.Writer
		switch header[0] {
		case 1:
			dst = stdout
		case 2:
			dst = stderr
		default:
			dst = io.Discard
		}
		if dst == nil {
			dst = io.Discard
		}
		if _, err := io.CopyN(dst, r, int64(size)); err != nil {
			return err
		}
	}
}

// parseImageRef splits "repo:tag" into repo and tag.
func parseImageRef(ref string) (string, string) {
	if i := strings.LastIndex(ref, ":"); i > 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, "latest"
}
