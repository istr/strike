// strike is a reproducible, rootless CI/CD lane executor.
package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/istr/strike/internal/capsule"
	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/front"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/transport"
)

// fatalWriter terminates the process if a write fails.
// A non-writable output means the audit trail is broken --
// continuing would produce unauditable results.
type fatalWriter struct{ w io.Writer }

func (f fatalWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err != nil {
		os.Exit(1)
	}
	return n, nil
}

const (
	artifactTypeImage = "image"
	artifactTypeFile  = "file"
)

const usage = `strike - reproducible, rootless CI/CD lanes

Usage:
  strike run      [lane.yaml]   Run a lane
  strike validate [lane.yaml]   Validate without running
  strike dag      [lane.yaml]   Show DAG and exit
  strike compare  <file1> <file2> <output>   Compare two files by SHA-256

Default file: lane.yaml in the current directory
`

func main() {
	log.SetFlags(0)
	log.SetOutput(fatalWriter{os.Stderr})

	if len(os.Args) < 2 {
		log.Print(usage)
		os.Exit(1)
	}

	// compare has its own arg layout.
	if os.Args[1] == "compare" {
		if len(os.Args) != 5 {
			log.Fatal("usage: strike compare <file1> <file2> <output>")
		}
		cmdCompare(os.Args[2], os.Args[3], os.Args[4])
		return
	}

	laneFile := "lane.yaml"
	if len(os.Args) >= 3 {
		laneFile = os.Args[2]
	}

	switch os.Args[1] {
	case "validate":
		cmdValidate(laneFile)
	case "dag":
		cmdDAG(laneFile)
	case "run":
		ctx := context.Background()
		engine := initEngine(ctx)
		cmdRun(ctx, laneFile, engine)
	default:
		log.Print(usage)
		os.Exit(1)
	}
}

func initEngine(ctx context.Context) container.Engine {
	engine, err := container.New()
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	if err := engine.Ping(ctx); err != nil {
		log.Fatalf("error: container engine not reachable: %v", err)
	}

	if err := engine.Info(ctx); err != nil {
		log.Fatalf("error: container engine info: %v "+
			"(strike requires Podman >= 5.0; the version gate cannot run without engine info)", err)
	}

	if err := container.RequireVersion(engine, "5.0.0"); err != nil {
		log.Fatalf("error: %v", err)
	}

	if id := engine.Identity(); id != nil {
		if id.Runtime != nil && !id.Runtime.Rootless {
			log.Print("WARN   engine is running as root -- rootless mode recommended")
		}
		switch id.Connection.Type {
		case "mtls":
			log.Printf("INFO   engine: mTLS, ca=%s (server=%s, client=%s)",
				id.Connection.CATrustMode, id.Connection.ServerCertSubject, id.Connection.ClientCertSubject)
		case "tls":
			log.Printf("INFO   engine: server-TLS, ca=%s (server=%s)",
				id.Connection.CATrustMode, id.Connection.ServerCertSubject)
		case "unix":
			// No log -- Unix socket is the normal case.
		}
	}
	return engine
}

// initRekor constructs a RekorClient from environment variables.
// Returns nil if REKOR_URL is not set (Rekor submission disabled).
// Fatals if REKOR_URL is set but REKOR_PUBLIC_KEY is missing or invalid --
// unverified Rekor responses provide no security value.
func initRekor() *executor.RekorClient {
	rekorURL := os.Getenv("REKOR_URL")
	if rekorURL == "" {
		return nil
	}

	pubKeyPath := os.Getenv("REKOR_PUBLIC_KEY")
	if pubKeyPath == "" {
		log.Fatal("error: REKOR_URL is set but REKOR_PUBLIC_KEY is not; " +
			"unverified rekor responses provide no security value")
	}

	pubKeyPEM, err := os.ReadFile(filepath.Clean(pubKeyPath))
	if err != nil {
		log.Fatalf("error: read rekor public key: %v", err)
	}

	pubKey, err := executor.ParseRekorPublicKey(pubKeyPEM)
	if err != nil {
		log.Fatalf("error: parse rekor public key: %v", err)
	}

	log.Printf("INFO   rekor: %s", sanitizeForLog(rekorURL))
	return &executor.RekorClient{
		PublicKey: pubKey,
		HTTP:      &http.Client{},
		URL:       rekorURL,
	}
}

func cmdValidate(path string) {
	fp, fpErr := lane.NewFilePath(path)
	if fpErr != nil {
		log.Fatalf("error: %v", fpErr)
	}
	p, err := lane.Parse(fp)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	if _, err := lane.Build(p); err != nil {
		log.Fatalf("error: DAG: %v", err)
	}
	log.Printf("ok: %s is valid (%d steps)", path, len(p.Steps)) // #nosec G706 -- path is a local file path from CLI args
}

func cmdDAG(path string) {
	fp, fpErr := lane.NewFilePath(path)
	if fpErr != nil {
		log.Fatalf("error: %v", fpErr)
	}
	p, err := lane.Parse(fp)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	dag, err := lane.Build(p)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	log.Print("Execution order:")
	for i, name := range dag.Order {
		edges := dag.InputEdges[name]
		deps := make([]string, len(edges))
		for j, e := range edges {
			deps[j] = string(e.FromStep.Name) + "." + e.FromOutput.Name
		}
		if len(deps) > 0 {
			log.Printf("  %d. %s <- %v", i+1, name, deps) // #nosec G706 -- name/deps from parsed lane YAML
		} else {
			log.Printf("  %d. %s", i+1, name) // #nosec G706 -- name from parsed lane YAML
		}
	}

	log.Print("\nDependency graph:")
	log.Print(dag.Tree()) // #nosec G706 -- internally generated DAG tree
}

func cmdRun(ctx context.Context, path string, engine container.Engine) {
	fp, fpErr := lane.NewFilePath(path)
	if fpErr != nil {
		log.Fatalf("error: %v", fpErr)
	}
	p, err := lane.Parse(fp)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	resolverID := probeResolver(ctx, p)
	laneDir := filepath.Dir(fp.String())
	laneRoot, err := os.OpenRoot(laneDir)
	if err != nil {
		log.Fatalf("error: open lane root: %v", err)
	}
	defer closer.Warn(laneRoot, "lane root")

	dag, err := lane.Build(p)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	ca, caCleanup := initLaneCA(p)
	defer caCleanup()

	ft, frontCleanup := initFront(ctx)
	defer frontCleanup()

	stepPorts := allocateMediatedPorts(p)

	upstreamLook := capsule.UpstreamLookupFunc(func(ctx context.Context, name string) ([]netip.Addr, error) {
		return transport.LookupHost(ctx, p.Resolver, name)
	})

	rc := &runContext{
		ctx:            ctx,
		engine:         engine,
		lane:           p,
		dag:            dag,
		regClient:      &registry.Client{Engine: engine},
		engineID:       engine.Identity(),
		ca:             ca,
		front:          ft,
		upstreamLook:   upstreamLook,
		state:          newRunState(),
		laneState:      lane.NewState(),
		stepPorts:      stepPorts,
		networkRecords: map[string]capsule.Records{},
		capsules:       map[string]*capsule.NetworkCapsule{},
		laneRoot:       laneRoot,
		rekor:          initRekor(),
		resolverID:     resolverID,
		laneDir:        laneDir,
	}

	if capsErr := rc.buildCapsules(ctx); capsErr != nil {
		log.Fatalf("error: %v", capsErr)
	}
	defer rc.stopCapsules()

	trust, trustErr := rc.planTrustVolumes(ctx, ca.PublicCertPEM())
	if trustErr != nil {
		log.Fatalf("error: %v", trustErr)
	}
	defer rc.removeTrustVolumes(context.Background(), trust)
	rc.trust = trust

	// Setup is complete: start serving the front. Until now it is bound (its
	// address was available to setup) but not accepting; the accept loop
	// begins only after all setup state is frozen (ADR-038 D2, bind-then-
	// serve).
	ft.Start(ctx)

	for _, stepName := range dag.Order {
		if stepErr := rc.runStep(stepName); stepErr != nil {
			log.Fatalf("error: %v", stepErr)
		}
	}

	// Dump final lane state for debugging and CI artifact collection.
	stateJSON, err := rc.laneState.JSON()
	if err != nil {
		log.Fatalf("error: marshal lane state: %v", err)
	}
	log.Printf("STATE  %s", stateJSON)
}

// probeResolver runs the pre-flight resolver probe. lane.Parse is a pure
// offline check; resolver reachability is an environmental property and
// therefore lives here, at run start, not in Parse. See
// docs/ROADMAP-ADR-028.md D16 for the rationale. The probe also captures
// the resolver's observed TLS identity, recorded in the deploy attestation
// per ADR-030.
func probeResolver(ctx context.Context, p *lane.Lane) transport.ConnectionIdentity {
	probeCtx, probeCancel := context.WithTimeout(ctx, 5*clock.Second)
	resolverID, probeErr := transport.ProbeResolver(probeCtx, p.Resolver)
	probeCancel()
	if probeErr != nil {
		log.Fatalf("error: %v", probeErr)
	}
	return resolverID
}

// initLaneCA creates the lane-wide ephemeral CA. The returned cleanup
// function closes the CA.
func initLaneCA(p *lane.Lane) (*transport.EphemeralCA, func()) {
	ca, caErr := transport.New(string(p.LaneID))
	if caErr != nil {
		log.Fatalf("error: ephemeral CA: %v", caErr)
	}
	return ca, func() { closer.Warn(ca, "ephemeral CA") }
}

// initFront starts the lane-run control-plane front (ADR-038 D2) on a host-
// loopback listener. In this skeleton the front owns only its listener and
// lifecycle; it does not yet terminate SSH or route by token (ADR-038 roadmap
// items 3 and 5). The returned cleanup closes it.
func initFront(ctx context.Context) (*front.Front, func()) {
	ft, ftErr := front.New(ctx)
	if ftErr != nil {
		log.Fatalf("error: front: %v", ftErr)
	}
	log.Printf("FRONT  bound @ %s", ft.Addr())
	return ft, func() { closer.Warn(ft, "front") }
}

// allocateMediatedPorts pre-allocates a host-port block for every
// container unit in lane-file order: each run step, each deploy step's
// method container (keyed by the step name), and each pre/post
// state-capture container (keyed "capture:<stepName>:<captureName>" to
// stay collision-free across parallel deploy steps). Pack steps launch
// no step container and are skipped.
func allocateMediatedPorts(p *lane.Lane) map[string]capsule.HostPorts {
	var reqs []capsule.StepPortReq
	for i := range p.Steps {
		s := &p.Steps[i]
		switch {
		case s.Pack != nil:
			continue
		case s.Deploy != nil:
			reqs = append(reqs, capsule.StepPortReq{Name: string(s.Name)})
			for _, sc := range s.Deploy.Attestation.PreState.Capture {
				reqs = append(reqs, capsule.StepPortReq{Name: captureKey(string(s.Name), sc.Name)})
			}
			for _, sc := range s.Deploy.Attestation.PostState.Capture {
				reqs = append(reqs, capsule.StepPortReq{Name: captureKey(string(s.Name), sc.Name)})
			}
		default:
			reqs = append(reqs, capsule.StepPortReq{Name: string(s.Name)})
		}
	}
	ports, err := capsule.AllocatePorts(reqs)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	return ports
}

// captureKey is the stepPorts map key for a state-capture container.
// Pre and post captures of the same name within one deploy step share
// a key (they run sequentially), but captures in different deploy
// steps do not collide.
func captureKey(stepName, captureName string) string {
	return "capture:" + stepName + ":" + captureName
}

func cmdCompare(file1, file2, output string) {
	safeFile1 := sanitizeForLog(file1)
	safeFile2 := sanitizeForLog(file2)
	safeOutput := sanitizeForLog(output)

	root1, err := os.OpenRoot(filepath.Dir(file1))
	if err != nil {
		log.Fatalf("error: %s: %v", safeFile1, err)
	}
	defer closer.Warn(root1, "compare root 1")
	h1, err := registry.HashFile(root1, filepath.Base(file1))
	if err != nil {
		log.Fatalf("error: %s: %v", safeFile1, err)
	}
	root2, err := os.OpenRoot(filepath.Dir(file2))
	if err != nil {
		log.Fatalf("error: %s: %v", safeFile2, err)
	}
	defer closer.Warn(root2, "compare root 2")
	h2, err := registry.HashFile(root2, filepath.Base(file2))
	if err != nil {
		log.Fatalf("error: %s: %v", safeFile2, err)
	}
	if h1 != h2 {
		log.Fatalf("error: files differ\n  %s: %s\n  %s: %s", safeFile1, h1, safeFile2, h2)
	}
	outRoot, err := os.OpenRoot(filepath.Dir(output))
	if err != nil {
		log.Fatalf("error: %s: %v", safeOutput, err)
	}
	defer closer.Warn(outRoot, "compare output root")
	outFile, err := outRoot.Create(filepath.Base(output))
	if err != nil {
		log.Fatalf("error: write %s: %v", safeOutput, err)
	}
	if _, writeErr := outFile.Write([]byte(h1.String() + "\n")); writeErr != nil {
		closer.Warn(outFile, "compare output")
		log.Fatalf("error: write %s: %v", safeOutput, writeErr)
	}
	if closeErr := outFile.Close(); closeErr != nil {
		log.Fatalf("error: write %s: %v", safeOutput, closeErr)
	}
	log.Printf("ok: %s", h1) // #nosec G706 -- h1 is a SHA-256 hex digest
}
