package container

import (
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
		e.identity.Connection.Type = "unix"
		return
	}

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		e.identity.Connection.Type = "tls"
		return
	}

	serverCert := resp.TLS.PeerCertificates[0]
	e.identity.Connection.ServerCertFingerprint = CertFingerprint(serverCert)
	e.identity.Connection.ServerCertSubject = serverCert.Subject.CommonName
	e.identity.Connection.ServerCertIssuer = serverCert.Issuer.CommonName

	if e.tlsCfg.HasClientCert() {
		e.identity.Connection.Type = "mtls"
		clientPair, loadErr := tls.LoadX509KeyPair(e.tlsCfg.CertFile, e.tlsCfg.KeyFile)
		if loadErr == nil && len(clientPair.Certificate) > 0 {
			clientCert, parseErr := x509.ParseCertificate(clientPair.Certificate[0])
			if parseErr == nil {
				e.identity.Connection.ClientCertFingerprint = CertFingerprint(clientCert)
				e.identity.Connection.ClientCertSubject = clientCert.Subject.CommonName
			}
		}
	} else {
		e.identity.Connection.Type = "tls"
	}

	if e.tlsCfg.IsPinned() {
		e.identity.Connection.CATrustMode = "pinned"
	} else {
		e.identity.Connection.CATrustMode = "system"
	}

	e.tlsID = &TLSIdentity{
		ServerFingerprint: e.identity.Connection.ServerCertFingerprint,
		ServerSubject:     e.identity.Connection.ServerCertSubject,
		ServerIssuer:      e.identity.Connection.ServerCertIssuer,
		ClientFingerprint: e.identity.Connection.ClientCertFingerprint,
		ClientSubject:     e.identity.Connection.ClientCertSubject,
		Mutual:            e.identity.Connection.Type == "mtls",
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
		Digest:      raw.Digest,
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

// runContainer creates, starts, streams logs from, and waits for a
// container. It does not remove the container. It returns the container id
// (valid for cleanup even when a post-create step errors) and the exit
// code. ContainerRun and ContainerRunHeld share this body.
func (e *podmanEngine) runContainer(ctx context.Context, opts RunOpts) (string, int, error) {
	id, err := e.containerCreate(ctx, opts)
	if err != nil {
		return "", -1, fmt.Errorf("container create: %w", err)
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
	id, exitCode, err := e.runContainer(ctx, opts)
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
// container survives for extraction by the caller.
func (e *podmanEngine) ContainerRunHeld(ctx context.Context, opts RunOpts) (string, int, error) {
	opts.Remove = false
	return e.runContainer(ctx, opts)
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
	var result struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
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

// buildSpecGenerator constructs the libpod SpecGenerator JSON from RunOpts.
func buildSpecGenerator(opts RunOpts) map[string]any {
	spec := map[string]any{
		"image":   opts.Image,
		"command": opts.Cmd,
		"remove":  opts.Remove,
	}

	// Entrypoint override
	if len(opts.Entrypoint) > 0 {
		spec["entrypoint"] = opts.Entrypoint
	}

	// Working directory
	if opts.Workdir != "" {
		spec["work_dir"] = opts.Workdir
	}

	// Environment
	if len(opts.Env) > 0 {
		spec["env"] = opts.Env
	}

	// Mounts (bind + tmpfs)
	if mounts := buildMounts(opts); len(mounts) > 0 {
		spec["mounts"] = mounts
	}

	// Named volume (the engine-managed writable workdir surface).
	if opts.Volume != nil {
		spec["volumes"] = buildVolumes(opts)
	}

	// Network
	if opts.Network != "" {
		spec["netns"] = map[string]string{"nsmode": opts.Network}
		if opts.Network == "pasta" && len(opts.PastaArgs) > 0 {
			spec["network_options"] = map[string]any{"pasta": opts.PastaArgs}
		}
	}
	// DNS server overrides (mediated steps point at the capsule's
	// resolver loopback address).
	if len(opts.DNSServers) > 0 {
		spec["dns_server"] = opts.DNSServers
	}

	// Security
	if len(opts.CapDrop) > 0 {
		spec["cap_drop"] = opts.CapDrop
	}
	if opts.ReadOnly {
		spec["read_only_filesystem"] = true
	}
	if len(opts.SecurityOpt) > 0 {
		spec["security_opt"] = opts.SecurityOpt
	}

	// User namespace
	if opts.UsernsMode != "" {
		spec["userns"] = map[string]string{"nsmode": opts.UsernsMode}
	}

	return spec
}

func buildMounts(opts RunOpts) []map[string]any {
	var mounts []map[string]any
	for _, m := range opts.Mounts {
		mount := map[string]any{
			"destination": m.Target,
			"source":      m.Source,
			"type":        "bind",
		}
		mountOpts := append([]string{}, m.Options...)
		if m.ReadOnly {
			mountOpts = append(mountOpts, "ro")
		}
		if len(mountOpts) > 0 {
			mount["options"] = mountOpts
		}
		mounts = append(mounts, mount)
	}
	for path, options := range opts.Tmpfs {
		mounts = append(mounts, map[string]any{
			"destination": path,
			"type":        "tmpfs",
			"options":     strings.Split(options, ","),
		})
	}
	return mounts
}

// buildVolumes wraps the single named volume into the array shape the
// libpod SpecGenerator expects under the "volumes" key.
func buildVolumes(opts RunOpts) []map[string]any {
	// VERIFY AGAINST LIVE ENGINE -- confirmed podman 5.4.2: the libpod
	// SpecGenerator names this key "volumes", with entries
	// {"Name","Dest","Options"}.
	v := opts.Volume
	entry := map[string]any{"Name": v.Name, "Dest": v.Dest}
	if len(v.Options) > 0 {
		entry["Options"] = v.Options
	}
	return []map[string]any{entry}
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
