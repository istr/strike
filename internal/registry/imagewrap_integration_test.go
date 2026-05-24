//go:build integration

package registry_test

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/istr/strike/internal/container"
)

func needsEngine(t *testing.T) container.Engine {
	t.Helper()
	if os.Getenv("STRIKE_INTEGRATION") == "0" {
		t.Skip("integration tests disabled (STRIKE_INTEGRATION=0)")
	}
	engine, err := container.New()
	if err != nil {
		t.Fatalf("no container engine: %v", err)
	}
	ctx := t.Context()
	if err := engine.Ping(ctx); err != nil {
		t.Fatalf("container engine not responding: %v", err)
	}
	return engine
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
