package container

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type podmanEngine struct {
	client   *http.Client
	tlsCfg   *TLSConfig
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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close

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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close

	var raw struct { //nolint:govet // fieldalignment: JSON decode struct, field order matches API
		Host struct {
			Security struct {
				SELinuxEnabled  bool `json:"selinuxEnabled"`
				AppArmorEnabled bool `json:"apparmorEnabled"`
			} `json:"security"`
			Rootless bool `json:"rootless"`
		} `json:"host"`
		Version struct {
			Version    string `json:"Version"`
			APIVersion string `json:"APIVersion"`
		} `json:"version"`
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
		Rootless:   raw.Host.Rootless,
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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close
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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close
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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close
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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close
	var result struct {
		Names []string `json:"Names"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("image load: decode response: %w", err)
	}
	if len(result.Names) == 0 {
		return "", fmt.Errorf("image load: no image ID in response")
	}
	return result.Names[0], nil
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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close
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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("image tag: status %d", resp.StatusCode)
	}
	return nil
}

// ContainerRun creates, starts, waits for, and removes a container.
func (e *podmanEngine) ContainerRun(ctx context.Context, opts RunOpts) (int, error) {
	// 1. Create
	id, err := e.containerCreate(ctx, opts)
	if err != nil {
		return -1, fmt.Errorf("container create: %w", err)
	}

	// 2. Start
	if startErr := e.containerStart(ctx, id); startErr != nil {
		return -1, fmt.Errorf("container start: %w", startErr)
	}

	// 3. Stream logs (stdout/stderr) in background
	done := make(chan error, 1)
	go func() {
		done <- e.containerLogs(ctx, id, opts.Stdout, opts.Stderr)
	}()

	// 4. Wait for exit
	exitCode, err := e.containerWait(ctx, id)
	if err != nil {
		return -1, fmt.Errorf("container wait: %w", err)
	}

	// 5. Wait for log streaming to finish
	if logErr := <-done; logErr != nil {
		// Log streaming errors are non-fatal
		if opts.Stderr != nil {
			fmt.Fprintf(opts.Stderr, "warning: log streaming: %v\n", logErr) //nolint:errcheck // best-effort warning
		}
	}

	// 6. Remove
	if opts.Remove {
		if rmErr := e.containerRemove(ctx, id); rmErr != nil {
			return exitCode, fmt.Errorf("container remove: %w", rmErr)
		}
	}

	return exitCode, nil
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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close
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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close
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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close
	var result struct {
		Error *struct {
			Message string
		} `json:"Error"`
		StatusCode int `json:"StatusCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return -1, err
	}
	if result.Error != nil && result.Error.Message != "" {
		return result.StatusCode, fmt.Errorf("wait: %s", result.Error.Message)
	}
	return result.StatusCode, nil
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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close
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
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort HTTP body close
	return nil
}

// buildSpecGenerator constructs the libpod SpecGenerator JSON from RunOpts.
func buildSpecGenerator(opts RunOpts) map[string]any {
	spec := map[string]any{
		"image":   opts.Image,
		"command": opts.Cmd,
		"remove":  opts.Remove,
	}

	// Environment
	if len(opts.Env) > 0 {
		spec["env"] = opts.Env
	}

	// Mounts
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

	// Tmpfs
	for path, options := range opts.Tmpfs {
		mounts = append(mounts, map[string]any{
			"destination": path,
			"type":        "tmpfs",
			"options":     strings.Split(options, ","),
		})
	}

	if len(mounts) > 0 {
		spec["mounts"] = mounts
	}

	// Network
	if opts.Network != "" {
		spec["netns"] = map[string]string{"nsmode": opts.Network}
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
