package registry_test

import (
	"archive/tar"
	"bytes"
	"io"
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
