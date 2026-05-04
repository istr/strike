package deploy_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/istr/strike/internal/deploy"
)

func TestStateDigest_Deterministic(t *testing.T) {
	captures := []deploy.CaptureSnap{
		deploy.NewCaptureSnap("version", "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000", []byte("v1.2.3\n")),
		deploy.NewCaptureSnap("config", "busybox@sha256:1111111111111111111111111111111111111111111111111111111111111111", []byte("{}")),
	}

	d1 := deploy.StateDigest(captures)
	d2 := deploy.StateDigest(captures)

	if d1 != d2 {
		t.Fatalf("same input produced different digests: %s vs %s", d1, d2)
	}
	if d1.Algorithm != "sha256" {
		t.Errorf("Algorithm = %q, want sha256", d1.Algorithm)
	}
	if len(d1.Hex) != 64 {
		t.Errorf("Hex length = %d, want 64", len(d1.Hex))
	}
}

func TestStateDigest_OrderIndependent(t *testing.T) {
	a := deploy.NewCaptureSnap("version", "alpine@sha256:aaaa", []byte("v1"))
	b := deploy.NewCaptureSnap("config", "alpine@sha256:bbbb", []byte("cfg"))
	c := deploy.NewCaptureSnap("replicas", "alpine@sha256:cccc", []byte("3"))

	// Present in reverse-alphabetical order.
	d1 := deploy.StateDigest([]deploy.CaptureSnap{a, c, b})
	// Present in alphabetical order.
	d2 := deploy.StateDigest([]deploy.CaptureSnap{b, c, a})
	// Present in yet another order.
	d3 := deploy.StateDigest([]deploy.CaptureSnap{c, a, b})

	if d1 != d2 {
		t.Fatalf("order 1 vs 2: %s != %s", d1, d2)
	}
	if d1 != d3 {
		t.Fatalf("order 1 vs 3: %s != %s", d1, d3)
	}
}

func TestStateDigest_ContentSensitive(t *testing.T) {
	base := deploy.NewCaptureSnap(
		"version",
		"alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		[]byte("v1.0.0"),
	)
	baseline := deploy.StateDigest([]deploy.CaptureSnap{base})

	tests := []struct {
		desc    string
		capture deploy.CaptureSnap
	}{
		{
			desc:    "different name",
			capture: deploy.NewCaptureSnap("versioN", "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000", []byte("v1.0.0")),
		},
		{
			desc:    "different image",
			capture: deploy.NewCaptureSnap("version", "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000001", []byte("v1.0.0")),
		},
		{
			desc:    "different output",
			capture: deploy.NewCaptureSnap("version", "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000", []byte("v1.0.1")),
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			d := deploy.StateDigest([]deploy.CaptureSnap{tc.capture})
			if d == baseline {
				t.Errorf("changing %s did not change the digest", tc.desc)
			}
		})
	}
}

func TestStateDigest_Empty(t *testing.T) {
	d := deploy.StateDigest(nil)

	if d.Algorithm != "sha256" {
		t.Fatalf("Algorithm = %q, want sha256", d.Algorithm)
	}
	// SHA-256 of the empty byte sequence.
	const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if d.Hex != emptyHash {
		t.Fatalf("Hex = %q, want %q", d.Hex, emptyHash)
	}
}

const stateDigestCrossvalDir = "../../test/crossval/state_digest"

type stateDigestVector struct {
	Description string `json:"description"`
	Boundary    string `json:"boundary"`
	Expected    struct {
		Digest string `json:"digest"`
	} `json:"expected"`
	Inputs struct {
		Captures []struct {
			Name         string `json:"name"`
			Image        string `json:"image"`
			OutputBase64 string `json:"output_base64"`
		} `json:"captures"`
	} `json:"inputs"`
}

func TestStateDigest_Golden(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(stateDigestCrossvalDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no state_digest vectors found")
	}

	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(f) //nolint:gosec // G304: path from hardcoded test constant
			if err != nil {
				t.Fatalf("read vector: %v", err)
			}
			var vec stateDigestVector
			if err := json.Unmarshal(data, &vec); err != nil {
				t.Fatalf("unmarshal vector: %v", err)
			}

			captures := make([]deploy.CaptureSnap, len(vec.Inputs.Captures))
			for i, c := range vec.Inputs.Captures {
				output, decErr := base64.StdEncoding.DecodeString(c.OutputBase64)
				if decErr != nil {
					t.Fatalf("decode output_base64 for %q: %v", c.Name, decErr)
				}
				captures[i] = deploy.NewCaptureSnap(c.Name, c.Image, output)
			}

			got := deploy.StateDigest(captures)
			if got.String() != vec.Expected.Digest {
				t.Errorf("digest mismatch:\n  got:  %s\n  want: %s", got, vec.Expected.Digest)
			}
		})
	}
}
