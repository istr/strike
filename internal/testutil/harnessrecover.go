package testutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/transport"
)

// Recovery budgets. readyBudget bounds the whole readiness phase rather than
// each probe: a restart brings every service up in parallel, so one shared
// deadline is both simpler and tighter than a budget per endpoint. It is an
// upper bound, not an expectation.
const (
	readyBudget  = 180 * clock.Second
	pollInterval = 2 * clock.Second
	probeTimeout = 10 * clock.Second
)

// composeProjectLabel is the label every container of a compose project
// carries. Addressing by label rather than by derived container name keeps
// the recovery path independent of the name suffix a particular compose
// provider happens to use.
const composeProjectLabel = "com.docker.compose.project"

// Functional readiness endpoints, reached through the harness TLS terminator.
const (
	issuerDiscoveryURL = "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore/.well-known/openid-configuration"
	logHealthURL       = "https://rekor.127.0.0.1.sslip.io:3003/healthz"
	ctLogHealthURL     = "https://ct.127.0.0.1.sslip.io:6962/healthz"
	tsaCertChainURL    = "https://tsa.127.0.0.1.sslip.io:3004/api/v1/timestamp/certchain"
)

// RequireHarness makes the local sigstore harness usable for the calling
// test. Containers that exist but are stopped are started again, readiness is
// polled, and the timestamp authority's certificate chain is re-exported --
// that authority signs with an in-memory key and mints a fresh certificate on
// every start, so a chain exported before a restart no longer verifies what
// is produced after it.
//
// Recovery is not creation. The harness must already exist; a container set
// whose image digests no longer match the declaration is reported rather than
// started, because starting it would run an image the declaration no longer
// names.
//
// eng is assumed to be the engine that holds the harness. Today that is the
// same engine steps run on. If it ever is not, the failure names the address
// that was queried, so the mismatch is visible rather than silent.
func RequireHarness(t *testing.T, eng container.Engine, harnessDir string) {
	t.Helper()
	if err := recoverHarness(t.Context(), eng, harnessDir); err != nil {
		t.Fatalf("%v; set STRIKE_INTEGRATION=0 to skip integration tests", err)
	}
}

// recoverHarness restarts the stopped harness and refreshes its rotating
// anchor. Errors are bare: the opt-out hint belongs to the caller that can
// act on it.
func recoverHarness(ctx context.Context, eng container.Engine, dir string) error {
	cold := fmt.Sprintf("the harness needs a cold start: make -C %s up", dir)
	project, want, err := composeServices(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		return err
	}
	got, err := eng.ContainerList(ctx, composeProjectLabel+"="+project)
	if err != nil {
		return fmt.Errorf("list harness containers on engine %s: %w", engineAddress(), err)
	}
	if len(got) == 0 {
		return fmt.Errorf("engine %s holds no container of compose project %s; %s",
			engineAddress(), project, cold)
	}
	toStart, err := harnessDrift(want, got)
	if err != nil {
		return fmt.Errorf("%w; %s", err, cold)
	}
	for _, id := range toStart {
		if startErr := eng.ContainerStart(ctx, id); startErr != nil {
			return fmt.Errorf("start harness container %s: %w", id, startErr)
		}
	}
	caddyRoot := filepath.Join(dir, "pki", "caddy-root.crt")
	if _, statErr := os.Stat(caddyRoot); statErr != nil {
		return fmt.Errorf("harness root certificate %s missing; %s", caddyRoot, cold)
	}
	if readyErr := waitHarnessReady(ctx, caddyRoot); readyErr != nil {
		return readyErr
	}
	return refreshTSAChain(ctx, caddyRoot, filepath.Join(dir, "pki"))
}

// engineAddress reports the engine address the recovery path talked to. An
// unset variable is reported as unset rather than guessed, because the
// address is the one fact that distinguishes an absent harness from a query
// against the wrong engine.
func engineAddress() string {
	if addr := os.Getenv("CONTAINER_HOST"); addr != "" {
		return addr
	}
	return "(CONTAINER_HOST unset)"
}

// composeServices returns the project name and a map from image digest to
// service name for every service in the default profile. The digest is the
// comparison key because the engine reports a container's image fully
// qualified and without the tag, so only the content address is stable
// across both spellings.
func composeServices(path string) (string, map[string]string, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", nil, fmt.Errorf("read compose file: %w", err)
	}
	var doc struct {
		Services map[string]struct {
			Image    string   `yaml:"image"`
			Profiles []string `yaml:"profiles"`
		} `yaml:"services"`
		Name string `yaml:"name"`
	}
	if unmarshalErr := yaml.Unmarshal(raw, &doc); unmarshalErr != nil {
		return "", nil, fmt.Errorf("parse compose file: %w", unmarshalErr)
	}
	if doc.Name == "" {
		return "", nil, errors.New("compose file declares no project name")
	}
	want := make(map[string]string, len(doc.Services))
	for name, svc := range doc.Services {
		if len(svc.Profiles) > 0 || svc.Image == "" {
			continue
		}
		digest, digestErr := imageDigest(svc.Image)
		if digestErr != nil {
			return "", nil, fmt.Errorf("service %s: %w", name, digestErr)
		}
		want[digest] = name
	}
	if len(want) == 0 {
		return "", nil, errors.New("compose file declares no default-profile service")
	}
	return doc.Name, want, nil
}

// harnessDrift compares what the engine reports against what the compose file
// declares, and returns the ids of the containers that are not running. A
// mismatch is an error and not a repair: digest pinning exists so that a
// running container can be held to the declaration that named it.
func harnessDrift(want map[string]string, got []container.Summary) ([]string, error) {
	if len(got) != len(want) {
		return nil, fmt.Errorf("harness holds %d container(s), the compose file declares %d service(s)",
			len(got), len(want))
	}
	seen := make(map[string]bool, len(want))
	toStart := make([]string, 0, len(got))
	for _, c := range got {
		digest, err := imageDigest(c.Image)
		if err != nil {
			return nil, fmt.Errorf("container %s: %w", containerName(c), err)
		}
		service, declared := want[digest]
		if !declared {
			return nil, fmt.Errorf("container %s runs image %s, which no declared service names",
				containerName(c), c.Image)
		}
		if seen[digest] {
			return nil, fmt.Errorf("service %s has more than one container", service)
		}
		seen[digest] = true
		if c.State != "running" {
			toStart = append(toStart, c.ID)
		}
	}
	return toStart, nil
}

// containerName reports the first name the engine gave a container, or its id
// when the engine reported no name.
func containerName(c container.Summary) string {
	if len(c.Names) > 0 {
		return c.Names[0]
	}
	return c.ID
}

// imageDigest extracts the content address from an image reference. A
// reference without one is rejected: it cannot be compared across spellings,
// and the harness declares none.
func imageDigest(ref string) (string, error) {
	_, digest, found := strings.Cut(ref, "@")
	if !found || digest == "" {
		return "", fmt.Errorf("image reference %q carries no digest", ref)
	}
	return digest, nil
}

// waitHarnessReady polls the readiness endpoints the harness exposes through
// its TLS terminator. Verification is pinned to the exported internal root
// and never skipped.
func waitHarnessReady(ctx context.Context, caddyRoot string) error {
	client, err := pinnedClient(caddyRoot, 0)
	if err != nil {
		return err
	}
	deadline, cancel := context.WithTimeout(ctx, readyBudget)
	defer cancel()
	probes := []struct {
		name string
		url  string
		want string
	}{
		{"issuer", issuerDiscoveryURL, ""},
		{"transparency log", logHealthURL, "SERVING"},
		{"ct log", ctLogHealthURL, ""},
	}
	for _, p := range probes {
		if probeErr := probeReady(deadline, client, p.url, p.want); probeErr != nil {
			return fmt.Errorf("harness %s not ready: %w", p.name, probeErr)
		}
	}
	return nil
}

// probeReady retries one endpoint until it answers, or until the deadline
// expires. The pause between attempts is a scoped context deadline rather
// than a sleep, so a cancelled parent ends the loop on the next check.
func probeReady(ctx context.Context, client *http.Client, url, want string) error {
	for {
		last := probeOnce(ctx, client, url, want)
		if last == nil {
			return nil
		}
		pause, cancel := context.WithTimeout(ctx, pollInterval)
		<-pause.Done()
		cancel()
		if ctx.Err() != nil {
			return fmt.Errorf("%w (last attempt: %w)", ctx.Err(), last)
		}
	}
}

// probeOnce performs one readiness request. An empty want checks the status
// only; a non-empty want must appear in the body.
func probeOnce(ctx context.Context, client *http.Client, url, want string) error {
	reqCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close readiness response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	if want == "" {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if !strings.Contains(string(body), want) {
		return fmt.Errorf("body does not report %s", want)
	}
	return nil
}

// refreshTSAChain re-exports the timestamp authority's certificate chain. The
// write is atomic because two test binaries can reach this point at the same
// time; both fetch the same chain from the same authority, so a last-writer
// outcome is correct as long as no reader observes a partial file.
func refreshTSAChain(ctx context.Context, caddyRoot, pkiDir string) error {
	client, err := pinnedClient(caddyRoot, 0)
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, tsaCertChainURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch timestamp certificate chain: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close timestamp certchain response: %v", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch timestamp certificate chain: status %d", resp.StatusCode)
	}
	chain, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read timestamp certificate chain: %w", err)
	}
	return writeAtomic(filepath.Join(pkiDir, "tsa-certchain.pem"), chain)
}

// writeAtomic replaces path through a temporary file in the same directory,
// so a concurrent reader never observes a half-written file. The temporary
// file keeps its default owner-only mode: the chain is read by the test
// process, never by a container.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	name := tmp.Name()
	renamed := false
	defer func() {
		if renamed {
			return
		}
		if rmErr := os.Remove(name); rmErr != nil {
			log.Printf("WARN remove %s: %v", name, rmErr)
		}
	}()
	if _, writeErr := tmp.Write(data); writeErr != nil {
		return fmt.Errorf("write %s: %w", name, writeErr)
	}
	if closeErr := tmp.Close(); closeErr != nil {
		return fmt.Errorf("close %s: %w", name, closeErr)
	}
	if renameErr := os.Rename(name, path); renameErr != nil {
		return fmt.Errorf("rename %s to %s: %w", name, path, renameErr)
	}
	renamed = true
	return nil
}

// pinnedClient returns a client that validates the harness endpoints against
// the exported internal root. timeout bounds one whole round trip; pass zero
// to leave the bound to the caller's context, which is what the readiness
// probes do.
func pinnedClient(caCertPath string, timeout clock.Duration) (*http.Client, error) {
	cfg, err := transport.BuildTLSConfig(endpoint.CABundle{
		Type: "caBundle",
		Path: primitive.AbsPath(caCertPath),
	})
	if err != nil {
		return nil, fmt.Errorf("harness tls config: %w", err)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: timeout}, nil
}
