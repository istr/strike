package main

import (
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// syntheticBlob builds a token the scanner accepts without putting a literal
// DER blob in this file, which the gate would then report.
func syntheticBlob(tail string) string {
	return string(derBlobPrefix) + strings.Repeat("A", derBlobMinLen) + tail
}

func TestIsBlobByte(t *testing.T) {
	for _, b := range []byte("Az09+/=-_") {
		if !isBlobByte(b) {
			t.Errorf("isBlobByte(%q) = false, want true", b)
		}
	}
	for _, b := range []byte(" \n\":,.#*`") {
		if isBlobByte(b) {
			t.Errorf("isBlobByte(%q) = true, want false", b)
		}
	}
}

func TestDerBlobTokens(t *testing.T) {
	long := syntheticBlob("")
	tests := []struct {
		name    string
		content string
		wantOff []int
	}{
		{name: "empty", content: "", wantOff: nil},
		{name: "no prefix", content: strings.Repeat("A", 200), wantOff: nil},
		{name: "prefix too short", content: string(derBlobPrefix) + "AAAA", wantOff: nil},
		{name: "bare token", content: long, wantOff: []int{0}},
		{name: "quoted in json", content: `{"rawBytes":"` + long + `"}`, wantOff: []int{13}},
		{name: "base64url tail is one token", content: long + "-_", wantOff: []int{0}},
		{name: "two on separate lines", content: long + "\n" + long + "\n", wantOff: []int{0, len(long) + 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := derBlobTokens([]byte(tt.content))
			if len(got) != len(tt.wantOff) {
				t.Fatalf("hits = %d, want %d", len(got), len(tt.wantOff))
			}
			for i := range got {
				if got[i].off != tt.wantOff[i] {
					t.Fatalf("hit %d offset = %d, want %d", i, got[i].off, tt.wantOff[i])
				}
			}
		})
	}
}

func TestDerBlobTokensKeepsWholeToken(t *testing.T) {
	content := syntheticBlob("-_")
	got := derBlobTokens([]byte(content))
	if len(got) != 1 {
		t.Fatalf("hits = %d, want 1", len(got))
	}
	if string(got[0].token) != content {
		t.Fatalf("token = %q, want %q", got[0].token, content)
	}
}

func TestDerBlobsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	recorded := 0
	for _, b := range derBlobs {
		if len(b.digest) != 64 {
			t.Errorf("digest %q is not 64 hex characters", b.digest)
		}
		if strings.ToLower(b.digest) != b.digest {
			t.Errorf("digest %q is not lowercase", b.digest)
		}
		if b.label == "" {
			t.Errorf("digest %q has no label", b.digest)
		}
		if seen[b.digest] {
			t.Errorf("digest %q is listed twice", b.digest)
		}
		seen[b.digest] = true
		if b.recorded {
			recorded++
		}
	}
	if len(derBlobs) != 23 {
		t.Errorf("allowlist has %d entries, want 23", len(derBlobs))
	}
	if recorded != 5 {
		t.Errorf("recorded entries = %d, want 5", recorded)
	}
}

func TestLookupBlob(t *testing.T) {
	const anchor = "348de86f9feea9730bf327ee217f5ab446d32b0e03a4e76002acfe01c24d7ff7"
	b, ok := lookupBlob(anchor)
	if !ok {
		t.Fatal("anchor digest not found in the allowlist")
	}
	if !b.recorded {
		t.Error("anchor entry is not marked as recorded")
	}
	if _, ok := lookupBlob(strings.Repeat("0", 64)); ok {
		t.Error("an absent digest was found")
	}
}

// tempGate opens a gate over a fresh directory the test owns.
func tempGate(t *testing.T) (*gate, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := root.Close(); closeErr != nil {
			t.Errorf("close root: %v", closeErr)
		}
	})
	return &gate{root: root, fset: token.NewFileSet()}, dir
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func TestCheckDERBlobs(t *testing.T) {
	g, dir := tempGate(t)
	writeFile(t, dir, "clean.json", `{"note":"nothing here"}`)
	writeFile(t, dir, "sub/dirty.yaml", "cert: "+syntheticBlob(""))
	writeFile(t, dir, "pki/ephemeral.crt", syntheticBlob(""))
	writeFile(t, dir, "pki/ephemeral.key", syntheticBlob(""))
	writeFile(t, dir, "build/artifact", "\x00ELF"+syntheticBlob(""))
	if err := g.checkDERBlobs(); err != nil {
		t.Fatalf("checkDERBlobs: %v", err)
	}
	if len(g.found) != 1 {
		t.Fatalf("findings = %v, want exactly one", g.found)
	}
	if !strings.Contains(g.found[0], unlistedBlobMessage) {
		t.Errorf("finding = %q, want the unlisted-blob message", g.found[0])
	}
	if !strings.Contains(g.found[0], "sub/dirty.yaml") {
		t.Errorf("finding = %q, want the offending path", g.found[0])
	}
}

func TestCheckAnchorRecordMissing(t *testing.T) {
	g, dir := tempGate(t)
	writeFile(t, dir, anchorDocPath, "# nothing recorded here\n")
	if err := g.checkAnchorRecord(); err != nil {
		t.Fatalf("checkAnchorRecord: %v", err)
	}
	if len(g.found) != 5 {
		t.Fatalf("findings = %d, want 5", len(g.found))
	}
	for _, f := range g.found {
		if !strings.Contains(f, missingRecordMessage) {
			t.Errorf("finding = %q, want the missing-artifact message", f)
		}
	}
}

func TestCheckAnchorRecordStray(t *testing.T) {
	g, dir := tempGate(t)
	writeFile(t, dir, anchorDocPath, syntheticBlob("")+"\n")
	if err := g.checkAnchorRecord(); err != nil {
		t.Fatalf("checkAnchorRecord: %v", err)
	}
	var stray int
	for _, f := range g.found {
		if strings.Contains(f, strayRecordMessage) {
			stray++
		}
	}
	if stray != 1 {
		t.Fatalf("stray findings = %d in %v, want 1", stray, g.found)
	}
}

func TestIsBinary(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{name: "text", content: "cert: " + syntheticBlob(""), want: false},
		{name: "nul at the start", content: "\x00ELF", want: true},
		{name: "nul inside the sniff window", content: strings.Repeat("a", 100) + "\x00", want: true},
		{name: "nul beyond the sniff window", content: strings.Repeat("a", binarySniffLen) + "\x00", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBinary([]byte(tt.content)); got != tt.want {
				t.Fatalf("isBinary = %v, want %v", got, tt.want)
			}
		})
	}
}
