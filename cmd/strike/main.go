// strike is a reproducible, rootless CI/CD lane executor.
package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/executor"
	"github.com/istr/strike/internal/lane"
	"github.com/istr/strike/internal/registry"
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

const artifactTypeImage = "image"

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
		log.Printf("WARN   engine info unavailable: %v", err)
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
	p, err := lane.Parse(path)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	if _, err := lane.Build(p); err != nil {
		log.Fatalf("error: DAG: %v", err)
	}
	log.Printf("ok: %s is valid (%d steps)", path, len(p.Steps)) // #nosec G706 -- path is a local file path from CLI args
}

func cmdDAG(path string) {
	p, err := lane.Parse(path)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	dag, err := lane.Build(p)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	log.Print("Execution order:")
	for i, name := range dag.Order {
		step := dag.Steps[name]
		deps := []string{}
		for _, inp := range step.Inputs {
			deps = append(deps, inp.From)
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
	p, err := lane.Parse(path)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		log.Fatalf("error: resolve lane path: %v", err)
	}
	laneDir := filepath.Dir(absPath)

	laneRoot, err := os.OpenRoot(laneDir)
	if err != nil {
		log.Fatalf("error: open lane root: %v", err)
	}
	defer laneRoot.Close() //nolint:errcheck // best-effort cleanup on exit

	dag, err := lane.Build(p)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	rc := &runContext{
		ctx:       ctx,
		engine:    engine,
		lane:      p,
		dag:       dag,
		regClient: &registry.Client{Engine: engine},
		engineID:  engine.Identity(),
		state:     newRunState(),
		laneState: lane.NewState(),
		laneRoot:  laneRoot,
		rekor:     initRekor(),
		laneDir:   laneDir,
	}
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

func cmdCompare(file1, file2, output string) {
	safeFile1 := sanitizeForLog(file1)
	safeFile2 := sanitizeForLog(file2)
	safeOutput := sanitizeForLog(output)

	h1, err := registry.HashFileAbs(file1)
	if err != nil {
		log.Fatalf("error: %s: %v", safeFile1, err)
	}
	h2, err := registry.HashFileAbs(file2)
	if err != nil {
		log.Fatalf("error: %s: %v", safeFile2, err)
	}
	if h1 != h2 {
		log.Fatalf("error: files differ\n  %s: %s\n  %s: %s", safeFile1, h1, safeFile2, h2)
	}
	cleanOutput := filepath.Clean(output)
	if err := os.WriteFile(cleanOutput, []byte(h1.String()+"\n"), 0o600); err != nil { //nolint:gosec // G703 - output path comes from CLI args, validated by filepath.Clean
		log.Fatalf("error: write %s: %v", safeOutput, err)
	}
	log.Printf("ok: %s", h1) // #nosec G706 -- h1 is a SHA-256 hex digest
}
