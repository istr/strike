package registry_test

import (
	"archive/tar"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/istr/strike/internal/registry"
)

// tarEntries reads a tar and returns a map of name -> content for regular
// files, a list of directory names, and a map of symlink name -> target.
func tarEntries(t *testing.T, data []byte) (files map[string]string, dirs []string, links map[string]string) {
	t.Helper()
	files = make(map[string]string)
	links = make(map[string]string)
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			b, readErr := io.ReadAll(tr)
			if readErr != nil {
				t.Fatalf("read %q: %v", hdr.Name, readErr)
			}
			files[hdr.Name] = string(b)
			if hdr.Uid != 0 || hdr.Gid != 0 {
				t.Errorf("entry %q: uid=%d gid=%d, want 0", hdr.Name, hdr.Uid, hdr.Gid)
			}
			if !hdr.ModTime.IsZero() && hdr.ModTime.Unix() != 0 {
				t.Errorf("entry %q: mtime=%v, want zero", hdr.Name, hdr.ModTime)
			}
		case tar.TypeDir:
			dirs = append(dirs, strings.TrimSuffix(hdr.Name, "/"))
		case tar.TypeSymlink:
			links[hdr.Name] = hdr.Linkname
		}
	}
	return files, dirs, links
}

func TestSeedTarFromImage_WholeLayerDirectory(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeDir, Name: "dir/", Mode: 0o755},
		{Typeflag: tar.TypeReg, Name: "dir/a.txt", Mode: 0o644},
		{Typeflag: tar.TypeReg, Name: "dir/b.txt", Mode: 0o644},
	}, map[string][]byte{
		"dir/a.txt": []byte("aaa"),
		"dir/b.txt": []byte("bbb"),
	})
	imgTar := buildSingleLayerImageTar(t, layerTar)

	got, err := registry.SeedTarFromImage(imgTar, "", "work")
	if err != nil {
		t.Fatal(err)
	}
	files, dirs, _ := tarEntries(t, got)
	if len(dirs) != 1 || dirs[0] != "work/dir" {
		t.Errorf("dirs = %v, want [work/dir]", dirs)
	}
	if files["work/dir/a.txt"] != "aaa" {
		t.Errorf("a.txt = %q, want %q", files["work/dir/a.txt"], "aaa")
	}
	if files["work/dir/b.txt"] != "bbb" {
		t.Errorf("b.txt = %q, want %q", files["work/dir/b.txt"], "bbb")
	}
}

func TestSeedTarFromImage_SubpathDirectory(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeDir, Name: "dir/", Mode: 0o755},
		{Typeflag: tar.TypeReg, Name: "dir/a.txt", Mode: 0o644},
		{Typeflag: tar.TypeReg, Name: "dir/b.txt", Mode: 0o644},
		{Typeflag: tar.TypeReg, Name: "outside.txt", Mode: 0o644},
	}, map[string][]byte{
		"dir/a.txt":   []byte("aaa"),
		"dir/b.txt":   []byte("bbb"),
		"outside.txt": []byte("nope"),
	})
	imgTar := buildSingleLayerImageTar(t, layerTar)

	got, err := registry.SeedTarFromImage(imgTar, "dir", "work/dir")
	if err != nil {
		t.Fatal(err)
	}
	files, _, _ := tarEntries(t, got)
	if files["work/dir/a.txt"] != "aaa" {
		t.Errorf("a.txt = %q, want %q", files["work/dir/a.txt"], "aaa")
	}
	if files["work/dir/b.txt"] != "bbb" {
		t.Errorf("b.txt = %q, want %q", files["work/dir/b.txt"], "bbb")
	}
	if _, ok := files["work/outside.txt"]; ok {
		t.Error("outside.txt should not be in output")
	}
}

func TestSeedTarFromImage_SingleFile(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "package.json", Mode: 0o644},
	}, map[string][]byte{
		"package.json": []byte(`{"name":"test"}`),
	})
	imgTar := buildSingleLayerImageTar(t, layerTar)

	// destPrefix is the full destination name; a single-file selection
	// emits exactly one entry named destPrefix.
	got, err := registry.SeedTarFromImage(imgTar, "package.json", "work")
	if err != nil {
		t.Fatal(err)
	}
	files, _, _ := tarEntries(t, got)
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(files), files)
	}
	if files["work"] != `{"name":"test"}` {
		t.Errorf("got files %v, want entry at %q", files, "work")
	}
}

func TestSeedTarFromImage_SingleFile_FullPathDestPrefix(t *testing.T) {
	// Producer layer shaped like a directory output: tree/package.json.
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeDir, Name: "tree/", Mode: 0o755},
		{Typeflag: tar.TypeReg, Name: "tree/package.json", Mode: 0o644},
	}, map[string][]byte{"tree/package.json": []byte(`{"name":"x"}`)})
	imgTar := buildSingleLayerImageTar(t, layerTar)

	// Caller passes destPrefix = the input's workdir-relative mount path.
	seed, err := registry.SeedTarFromImage(imgTar, "tree/package.json", "package.json")
	if err != nil {
		t.Fatal(err)
	}
	files, _, _ := tarEntries(t, seed)
	if files["package.json"] != `{"name":"x"}` {
		t.Errorf("files = %v, want entry at %q", files, "package.json")
	}
	if _, ok := files["package.json/package.json"]; ok {
		t.Error("double naming package.json/package.json present")
	}
}

func TestSeedTarFromImage_SingleFile_BareDestPrefix(t *testing.T) {
	// destPrefix "" or "." -> file keeps its basename.
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "solo.txt", Mode: 0o644},
	}, map[string][]byte{"solo.txt": []byte("x")})
	imgTar := buildSingleLayerImageTar(t, layerTar)

	seed, err := registry.SeedTarFromImage(imgTar, "solo.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	files, _, _ := tarEntries(t, seed)
	if files["solo.txt"] != "x" {
		t.Errorf("files = %v, want entry at %q", files, "solo.txt")
	}
	if _, ok := files["solo.txt/solo.txt"]; ok {
		t.Error("double naming solo.txt/solo.txt present")
	}
}

func TestSeedTarFromImage_Directory_NoDoubling(t *testing.T) {
	// Directory selection re-rooted under a full destPrefix: children only.
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeDir, Name: "tree/", Mode: 0o755},
		{Typeflag: tar.TypeDir, Name: "tree/packages/", Mode: 0o755},
		{Typeflag: tar.TypeReg, Name: "tree/packages/a.js", Mode: 0o644},
	}, map[string][]byte{"tree/packages/a.js": []byte("a")})
	imgTar := buildSingleLayerImageTar(t, layerTar)

	seed, err := registry.SeedTarFromImage(imgTar, "tree/packages", "packages")
	if err != nil {
		t.Fatal(err)
	}
	files, _, _ := tarEntries(t, seed)
	if files["packages/a.js"] != "a" {
		t.Errorf("files = %v, want entry at %q", files, "packages/a.js")
	}
	if _, ok := files["packages/packages/a.js"]; ok {
		t.Error("double prefix packages/packages/ present")
	}
}

func TestSeedTarFromImage_SubpathNotFound(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "hello.txt", Mode: 0o644},
	}, map[string][]byte{"hello.txt": []byte("hi")})
	imgTar := buildSingleLayerImageTar(t, layerTar)

	_, err := registry.SeedTarFromImage(imgTar, "missing", "work")
	if err == nil {
		t.Fatal("expected error for missing subpath")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error %q should mention 'missing'", err)
	}
}

func TestSeedTarFromImage_EscapingSymlinkRejected(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeSymlink, Name: "link", Linkname: "../../etc/passwd", Mode: 0o777},
	}, nil)
	imgTar := buildSingleLayerImageTar(t, layerTar)

	_, err := registry.SeedTarFromImage(imgTar, "", "work")
	if err == nil {
		t.Fatal("expected containment error")
	}
}

func TestSeedTarFromImage_ContainedSymlinkPreserved(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "sibling.txt", Mode: 0o644},
		{Typeflag: tar.TypeSymlink, Name: "link", Linkname: "sibling.txt", Mode: 0o777},
	}, map[string][]byte{"sibling.txt": []byte("content")})
	imgTar := buildSingleLayerImageTar(t, layerTar)

	got, err := registry.SeedTarFromImage(imgTar, "", "work")
	if err != nil {
		t.Fatal(err)
	}
	_, _, links := tarEntries(t, got)
	if links["work/link"] != "sibling.txt" {
		t.Errorf("link target = %q, want %q", links["work/link"], "sibling.txt")
	}
}

func TestSeedTarFromImage_Determinism(t *testing.T) {
	layerTar := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeDir, Name: "d/", Mode: 0o755},
		{Typeflag: tar.TypeReg, Name: "d/z.txt", Mode: 0o644},
		{Typeflag: tar.TypeReg, Name: "d/a.txt", Mode: 0o644},
	}, map[string][]byte{
		"d/z.txt": []byte("z"),
		"d/a.txt": []byte("a"),
	})
	imgTar := buildSingleLayerImageTar(t, layerTar)

	a, err := registry.SeedTarFromImage(imgTar, "", "out")
	if err != nil {
		t.Fatal(err)
	}
	b, err := registry.SeedTarFromImage(imgTar, "", "out")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two calls on the same input produced different tars")
	}
}

func TestSeedTarFromImage_MultiLayerRejected(t *testing.T) {
	layer1 := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "a.txt", Mode: 0o644},
	}, map[string][]byte{"a.txt": []byte("a")})
	layer2 := buildLayerTar(t, []tar.Header{
		{Typeflag: tar.TypeReg, Name: "b.txt", Mode: 0o644},
	}, map[string][]byte{"b.txt": []byte("b")})
	imgTar := buildOCIImageTar(t, layerFromTar(t, layer1), layerFromTar(t, layer2))

	_, err := registry.SeedTarFromImage(imgTar, "", "work")
	if err == nil {
		t.Fatal("expected error for multi-layer image")
	}
	if !strings.Contains(err.Error(), "1 content layer") {
		t.Errorf("error %q should mention expected layer count", err)
	}
}
