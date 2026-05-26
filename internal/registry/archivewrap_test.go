package registry_test

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/istr/strike/internal/registry"
)

type archiveEntry struct {
	content  string
	name     string
	linkname string
	mode     int64
	typeflag byte
}

func buildTar(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: e.mode, Linkname: e.linkname}
		if e.typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.content))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// readLayer returns the layer's uncompressed entries as a name-keyed map of
// headers, for assertions.
func readLayer(t *testing.T, layer interface{ Uncompressed() (io.ReadCloser, error) }) map[string]*tar.Header {
	t.Helper()
	rc, err := layer.Uncompressed()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := rc.Close(); closeErr != nil {
			t.Logf("close layer: %v", closeErr)
		}
	})
	out := map[string]*tar.Header{}
	tr := tar.NewReader(rc)
	for {
		hdr, readErr := tr.Next()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		out[hdr.Name] = hdr
	}
	return out
}

func TestCanonicalLayer_StripAndReroot(t *testing.T) {
	in := buildTar(t, []archiveEntry{
		{name: "work/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "work/sub/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "work/sub/a.txt", typeflag: tar.TypeReg, mode: 0o644, content: "aaa"},
	})
	layer, size, err := registry.CanonicalLayerFromTarForTest(bytes.NewReader(in), "work", "node_modules")
	if err != nil {
		t.Fatal(err)
	}
	if size != 3 {
		t.Errorf("size = %d, want 3", size)
	}
	got := readLayer(t, layer)
	if _, ok := got["node_modules/sub/a.txt"]; !ok {
		t.Errorf("missing re-rooted file; got keys %v", headerKeys(got))
	}
	if _, ok := got["work/sub/a.txt"]; ok {
		t.Error("prefix not stripped")
	}
}

func TestCanonicalLayer_ContainedSymlinkPreserved(t *testing.T) {
	in := buildTar(t, []archiveEntry{
		{name: "work/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "work/real.txt", typeflag: tar.TypeReg, mode: 0o644, content: "x"},
		{name: "work/link", typeflag: tar.TypeSymlink, linkname: "real.txt"},
	})
	layer, _, err := registry.CanonicalLayerFromTarForTest(bytes.NewReader(in), "work", "")
	if err != nil {
		t.Fatal(err)
	}
	got := readLayer(t, layer)
	h, ok := got["link"]
	if !ok || h.Typeflag != tar.TypeSymlink || h.Linkname != "real.txt" {
		t.Errorf("symlink not preserved verbatim: %+v", h)
	}
}

func TestCanonicalLayer_RejectsEscapingSymlink(t *testing.T) {
	in := buildTar(t, []archiveEntry{
		{name: "work/link", typeflag: tar.TypeSymlink, linkname: "../escape"},
	})
	if _, _, err := registry.CanonicalLayerFromTarForTest(bytes.NewReader(in), "work", ""); err == nil {
		t.Fatal("expected error for escaping symlink")
	}
}

func TestCanonicalLayer_RejectsAbsoluteSymlink(t *testing.T) {
	in := buildTar(t, []archiveEntry{
		{name: "work/link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
	})
	if _, _, err := registry.CanonicalLayerFromTarForTest(bytes.NewReader(in), "work", ""); err == nil {
		t.Fatal("expected error for absolute symlink")
	}
}

func TestCanonicalLayer_DeterministicRegardlessOfOrder(t *testing.T) {
	ordered := []archiveEntry{
		{name: "work/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "work/a.txt", typeflag: tar.TypeReg, mode: 0o644, content: "a"},
		{name: "work/b.txt", typeflag: tar.TypeReg, mode: 0o644, content: "b"},
		{name: "work/c.txt", typeflag: tar.TypeReg, mode: 0o644, content: "c"},
	}
	shuffled := []archiveEntry{ordered[3], ordered[1], ordered[0], ordered[2]}

	d1 := archiveLayerDigest(t, buildTar(t, ordered))
	d2 := archiveLayerDigest(t, buildTar(t, shuffled))
	if d1 != d2 {
		t.Errorf("layer digest depends on input order: %s vs %s", d1, d2)
	}
}

func archiveLayerDigest(t *testing.T, in []byte) string {
	t.Helper()
	layer, _, err := registry.CanonicalLayerFromTarForTest(bytes.NewReader(in), "work", "")
	if err != nil {
		t.Fatal(err)
	}
	d, err := layer.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d.String()
}

func headerKeys(m map[string]*tar.Header) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestCanonicalLayer_NoDoublePrefix_Directory(t *testing.T) {
	// Real engine shape for archiving /out/tree: entries prefixed "tree/".
	in := buildTar(t, []archiveEntry{
		{name: "tree/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "tree/package.json", typeflag: tar.TypeReg, mode: 0o644, content: "pkg"},
		{name: "tree/nested/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "tree/nested/a.txt", typeflag: tar.TypeReg, mode: 0o644, content: "a"},
	})

	// archiveReroot for a path "tree" directory: strip "tree", dest "tree".
	layer, _, err := registry.CanonicalLayerFromTarForTest(bytes.NewReader(in), "tree", "tree")
	if err != nil {
		t.Fatal(err)
	}
	got := readLayer(t, layer)
	if _, ok := got["tree/package.json"]; !ok {
		t.Errorf("missing tree/package.json; got keys %v", headerKeys(got))
	}
	if _, ok := got["tree/nested/a.txt"]; !ok {
		t.Errorf("missing tree/nested/a.txt; got keys %v", headerKeys(got))
	}
	if _, ok := got["tree/tree/package.json"]; ok {
		t.Error("double prefix tree/tree/ present")
	}
}

func TestCanonicalLayer_NoDoublePrefix_File(t *testing.T) {
	// Real engine shape for archiving a single file /out/binary: bare entry.
	in := buildTar(t, []archiveEntry{
		{name: "binary", typeflag: tar.TypeReg, mode: 0o755, content: "bin"},
	})

	// archiveReroot for a path "binary" file: strip "", dest "".
	layer, _, err := registry.CanonicalLayerFromTarForTest(bytes.NewReader(in), "", "")
	if err != nil {
		t.Fatal(err)
	}
	got := readLayer(t, layer)
	if _, ok := got["binary"]; !ok {
		t.Errorf("missing binary; got keys %v", headerKeys(got))
	}
	if _, ok := got["binary/binary"]; ok {
		t.Error("double prefix binary/binary present")
	}
}

func TestWrapArchiveAsImage_LeadingSlashEntriesAreKept(t *testing.T) {
	// Given "/"-rooted input (as from a hypothetical archive), stripPrefix=""
	// keeps every entry and re-roots under destPrefix. A regression that
	// strips a nonexistent base prefix drops all entries -> empty layer,
	// size 0 (the whole-workdir output bug).
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name, content string) {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Size:     int64(len(content)),
			Mode:     0o644,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	write("/lib/a.js", "alpha")
	write("/top.txt", "beta")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	eng := &wrapEngine{}
	client := &registry.Client{Engine: eng}
	_, size, err := client.WrapArchiveAsImage(context.Background(), &buf, "", "layer", "localhost/strike/l/s:h")
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if want := int64(len("alpha") + len("beta")); size != want {
		t.Fatalf("size = %d, want %d (entries dropped?)", size, want)
	}
	if len(eng.loadBodies) == 0 {
		t.Fatal("engine received no image load")
	}

	dest := filepath.Join(t.TempDir(), "out")
	if mkErr := os.MkdirAll(dest, 0o750); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}
	if extractErr := registry.ExtractSingleLayer(eng.loadBodies[0], dest); extractErr != nil {
		t.Fatalf("extract: %v", extractErr)
	}
	for rel, want := range map[string]string{
		"layer/lib/a.js": "alpha",
		"layer/top.txt":  "beta",
	} {
		got, readErr := os.ReadFile(filepath.Clean(filepath.Join(dest, rel)))
		if readErr != nil {
			t.Fatalf("read %s: %v", rel, readErr)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
}
