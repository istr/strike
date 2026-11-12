package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry/regtest"
	"github.com/istr/strike/internal/testutil"
)

// versionPath is versionFile as a layer names it.
const versionPath = "usr/lib/go/src/internal/buildcfg/zbootstrap.go"

// unknown is a well-formed digest no test registry holds.
const unknown = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

// goRoot is the content of a Go image that states release 1.2.3.
func goRoot(extra map[string]string) map[string]string {
	files := map[string]string{"usr/lib/go/": "", versionPath: "package buildcfg\n\nconst version = `go1.2.3`\n"}
	maps.Copy(files, extra)
	return files
}

// refusal makes the test registry answer 403 to every request of one method
// whose path contains part, from the moment it is armed. A test arms it after
// its pushes, which send requests of the same shape.
type refusal struct {
	method string
	part   string
	armed  atomic.Bool
}

// testNamespace starts an in-memory registry and returns the namespace its
// repositories live in (go-containerregistry dials plain HTTP for 127.0.0.1).
func testNamespace(t *testing.T, refuse *refusal) string {
	t.Helper()
	inner := regtest.Registry(t, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse != nil && refuse.armed.Load() && r.Method == refuse.method && strings.Contains(r.URL.Path, refuse.part) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	return u.Host + "/chainguard/"
}

// tarLayer returns an uncompressed layer of files, keyed by the name the
// layer gives them. A name that ends in a slash is a directory.
func tarLayer(t *testing.T, files map[string]string) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(files[name])), Typeflag: tar.TypeReg}
		if strings.HasSuffix(name, "/") {
			hdr.Typeflag = tar.TypeDir
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(files[name])); err != nil {
			t.Fatalf("tar content %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return static.NewLayer(buf.Bytes(), types.OCIUncompressedLayer)
}

// pushLayer makes tag name an index whose linux/amd64 image is layer, and
// returns the digests of the index and of that image.
func pushLayer(t *testing.T, tag string, layer v1.Layer) (index, manifest string) {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("image: %v", err)
	}
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add:        img,
		Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
	})
	ref, err := name.ParseReference(tag)
	if err != nil {
		t.Fatalf("reference: %v", err)
	}
	if err = remote.WriteIndex(ref, idx); err != nil {
		t.Fatalf("push %s: %v", tag, err)
	}
	indexDigest, err := idx.Digest()
	if err != nil {
		t.Fatalf("index digest: %v", err)
	}
	manifestDigest, err := img.Digest()
	if err != nil {
		t.Fatalf("manifest digest: %v", err)
	}
	return indexDigest.String(), manifestDigest.String()
}

// push is pushLayer for a layer of files.
func push(t *testing.T, tag string, files map[string]string) (index, manifest string) {
	t.Helper()
	return pushLayer(t, tag, tarLayer(t, files))
}

// planned runs plan over tree and returns the files it would write as text.
func planned(t *testing.T, ns string, tree fstest.MapFS, version string) (map[string]string, primitive.ImageRef, error) {
	t.Helper()
	files, goImage, err := newUpgrader(context.Background(), ns).plan(tree, version)
	text := map[string]string{}
	for name, content := range files {
		text[name] = string(content)
	}
	return text, goImage, err
}

func TestPlanMovesEachReferenceInItsForm(t *testing.T) {
	ns := testNamespace(t, nil)
	oldIndex, oldManifest := push(t, ns+"go:latest", goRoot(map[string]string{"old": ""}))
	newIndex, newManifest := push(t, ns+"go:latest", goRoot(nil))
	oldPython, _ := push(t, ns+"python:latest-dev", map[string]string{"old": ""})
	newPython, _ := push(t, ns+"python:latest-dev", map[string]string{"new": ""})

	containerfile := "FROM " + ns + "go@" + oldManifest + " AS build\n" +
		"COPY --from=" + ns + "go@" + oldManifest + " /usr/lib/go /usr/lib/go\n" +
		"COPY --from=build /a /b\n" +
		"COPY --chown=1:1 home/ /home/\n" +
		"RUN [\"go\", \"version\"]\n"
	stale := []byte("image: " + ns + "go@" + oldManifest + "\n")
	tree := fstest.MapFS{
		"a/Containerfile":      {Data: []byte(containerfile)},
		"b/lane.cue":           {Data: []byte("_go: \"" + ns + "go@" + oldIndex + "\"\n_py: \"" + ns + "python@" + oldPython + "\"\n")},
		"c/pins_test.go":       {Data: []byte("const missing = \"" + ns + "go@" + unknown + "\"\nconst now = \"" + ns + "go@" + newIndex + "\"\n")},
		"c/other.go":           {Data: []byte("const other = \"registry.example.com/go@" + oldManifest + "\"\n")},
		"docs/record.md":       {Data: stale},
		"lane.yaml":            {Data: stale},
		".git/hook.go":         {Data: stale},
		"nested/go.mod":        {Data: []byte("module nested\n")},
		"nested/Containerfile": {Data: stale},
	}
	got, goImage, err := planned(t, ns, tree, "1.2.3")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	want := map[string]string{
		"a/Containerfile": strings.ReplaceAll(containerfile, oldManifest, newManifest),
		"b/lane.cue":      "_go: \"" + ns + "go@" + newIndex + "\"\n_py: \"" + ns + "python@" + newPython + "\"\n",
	}
	if !maps.Equal(got, want) {
		t.Errorf("planned files = %v, want %v", got, want)
	}
	if wantImage := primitive.NewImageRef(ns + "go@" + newManifest); goImage != wantImage {
		t.Errorf("go image = %s, want %s", goImage, wantImage)
	}
}

func TestPlanFollowsATagThatNamesOneImage(t *testing.T) {
	ns := testNamespace(t, nil)
	push(t, ns+"go:latest", goRoot(nil))
	_, oldManifest := push(t, ns+"git:latest", map[string]string{"old": ""})
	img, err := mutate.AppendLayers(empty.Image, tarLayer(t, map[string]string{"new": ""}))
	if err != nil {
		t.Fatalf("image: %v", err)
	}
	ref, err := name.ParseReference(ns + "git:latest")
	if err != nil {
		t.Fatalf("reference: %v", err)
	}
	if err = remote.Write(ref, img); err != nil {
		t.Fatalf("push: %v", err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	tree := fstest.MapFS{"lane.cue": {Data: []byte(ns + "git@" + oldManifest)}}
	got, _, err := planned(t, ns, tree, "1.2.3")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if want := ns + "git@" + digest.String(); got["lane.cue"] != want {
		t.Errorf("lane.cue = %q, want %q", got["lane.cue"], want)
	}
}

func TestPlanChecksCopySources(t *testing.T) {
	tests := []struct {
		name    string
		sources string
		want    string
		wantErr []string
	}{
		{
			name:    "present paths stay",
			sources: "/usr/lib/go /usr/lib/libz.so.1",
			want:    "/usr/lib/go /usr/lib/libz.so.1",
		},
		{
			name:    "version suffix is renamed",
			sources: "/usr/lib/libz.so.1 /usr/lib/libz.so.1.3.2",
			want:    "/usr/lib/libz.so.1 /usr/lib/libz.so.1.3.3",
		},
		{
			name:    "missing paths are all reported",
			sources: "/usr/bin/gone /usr/lib/libz.so.1 /usr/lib/libq.so.5",
			wantErr: []string{"a/Containerfile:1: ", "go has no /usr/bin/gone", "go has no /usr/lib/libq.so.5"},
		},
		{
			name:    "two candidates are no rename",
			sources: "/usr/lib/libc.so /usr/lib/libc.so-2.44",
			wantErr: []string{"go has no /usr/lib/libc.so-2.44"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := testNamespace(t, nil)
			_, oldManifest := push(t, ns+"go:latest", goRoot(map[string]string{"old": ""}))
			_, newManifest := push(t, ns+"go:latest", goRoot(map[string]string{
				"usr/lib/libz.so.1":     "",
				"usr/lib/libz.so.1.3.3": "",
				"usr/lib/libc.so":       "",
				"usr/lib/libc.so-2.45":  "",
				"usr/lib/libc.so.6":     "",
			}))
			line := "COPY --from=" + ns + "go@%s " + tt.sources + " /usr/lib/\n"
			tree := fstest.MapFS{"a/Containerfile": {Data: []byte(strings.Replace(line, "%s", oldManifest, 1))}}
			got, _, err := planned(t, ns, tree, "1.2.3")
			for _, part := range tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), part) {
					t.Errorf("plan error = %v, want it to contain %q", err, part)
				}
			}
			if len(tt.wantErr) > 0 {
				return
			}
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			want := "COPY --from=" + ns + "go@" + newManifest + " " + tt.want + " /usr/lib/\n"
			if got["a/Containerfile"] != want {
				t.Errorf("Containerfile = %q, want %q", got["a/Containerfile"], want)
			}
		})
	}
}

func TestPlanLeavesACurrentReferenceUnchecked(t *testing.T) {
	ns := testNamespace(t, nil)
	_, manifest := push(t, ns+"go:latest", goRoot(nil))
	tree := fstest.MapFS{"Containerfile": {Data: []byte("COPY --from=" + ns + "go@" + manifest + " /usr/bin/gone /usr/bin/\n")}}
	got, _, err := planned(t, ns, tree, "1.2.3")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("planned files = %v, want none", got)
	}
}

func TestPlanRequiresTheStatedRelease(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{name: "another release", files: goRoot(nil), want: "go carries go 1.2.3, not go 1.2.4"},
		{name: "no version file", files: map[string]string{"usr/lib/go/": ""}, want: "go carries no stated release, not go 1.2.4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := testNamespace(t, nil)
			push(t, ns+"go:latest", tt.files)
			_, _, err := planned(t, ns, fstest.MapFS{}, "1.2.4")
			if err == nil || !strings.HasSuffix(err.Error(), tt.want) {
				t.Fatalf("plan error = %v, want suffix %q", err, tt.want)
			}
		})
	}
}

func TestPlanFailsOnTheRegistry(t *testing.T) {
	truncated := tarLayer(t, map[string]string{versionPath: "const version = `go1.2.3`"})
	cut, err := truncated.Uncompressed()
	if err != nil {
		t.Fatalf("layer: %v", err)
	}
	whole, err := io.ReadAll(cut)
	if err != nil {
		t.Fatalf("layer: %v", err)
	}
	tests := []struct {
		refuse *refusal
		layer  v1.Layer
		name   string
		tree   string
	}{
		{name: "no go image", tree: "lane.cue"},
		{name: "layer is no archive", tree: "lane.cue", layer: static.NewLayer([]byte("no archive"), types.OCIUncompressedLayer)},
		{name: "version file is cut short", tree: "lane.cue", layer: static.NewLayer(whole[:520], types.OCIUncompressedLayer)},
		{name: "layer cannot be read", tree: "lane.cue", layer: tarLayer(t, goRoot(nil)), refuse: &refusal{method: http.MethodGet, part: "/go/blobs/"}},
		{name: "pinned digest cannot be read", tree: "lane.cue", layer: tarLayer(t, goRoot(nil)), refuse: &refusal{method: http.MethodHead, part: "/git/manifests/sha256:"}},
		{name: "tag cannot be read", tree: "lane.cue", layer: tarLayer(t, goRoot(nil)), refuse: &refusal{method: http.MethodGet, part: "/git/manifests/latest"}},
		{name: "copy source image cannot be read", tree: "Containerfile", layer: tarLayer(t, goRoot(nil)), refuse: &refusal{method: http.MethodGet, part: "/git/blobs/"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := testNamespace(t, tt.refuse)
			if tt.layer != nil {
				pushLayer(t, ns+"go:latest", tt.layer)
			}
			_, oldGit := push(t, ns+"git:latest", map[string]string{"old": ""})
			push(t, ns+"git:latest", map[string]string{"usr/bin/git": ""})
			if tt.refuse != nil {
				tt.refuse.armed.Store(true)
			}
			tree := fstest.MapFS{tt.tree: {Data: []byte("COPY --from=" + ns + "git@" + oldGit + " /usr/bin/git /usr/bin/\n")}}
			if _, _, planErr := planned(t, ns, tree, "1.2.3"); planErr == nil {
				t.Fatal("plan succeeded, want an error")
			}
		})
	}
}

func TestPlanFailsOnTheTree(t *testing.T) {
	ns := testNamespace(t, nil)
	push(t, ns+"go:latest", goRoot(nil))
	u := newUpgrader(context.Background(), ns)
	if _, _, err := u.plan(os.DirFS(filepath.Join(t.TempDir(), "absent")), "1.2.3"); err == nil {
		t.Error("plan over a missing tree succeeded, want an error")
	}
	dir := t.TempDir()
	if err := os.Symlink("absent", filepath.Join(dir, "dangling.go")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, _, err := u.plan(os.DirFS(dir), "1.2.3"); err == nil {
		t.Error("plan over an unreadable file succeeded, want an error")
	}
	if err := u.follow("no reference", "go", unknown); err == nil {
		t.Error("follow of a malformed reference succeeded, want an error")
	}
	if _, err := u.image("UPPER"); err == nil {
		t.Error("image of a malformed repository succeeded, want an error")
	}
}

func TestRenamed(t *testing.T) {
	files := map[string]bool{
		"/usr/lib/libz.so.1":         true,
		"/usr/lib/libz.so.1.3.3":     true,
		"/usr/lib/libm.so":           true,
		"/usr/lib/libm.so.6":         true,
		"/usr/lib/libm.so-2.45":      true,
		"/usr/lib/sub/libz.so.1.9":   true,
		"/usr/lib/libq.so.5":         true,
		"/usr/lib/libq.so.5.1":       true,
		"/usr/lib/libq.so.5.1.debug": true,
	}
	tests := []struct {
		name string
		src  string
		want string
		srcs []string
	}{
		{name: "soname and full version", src: "/usr/lib/libz.so.1.3.2", srcs: []string{"/usr/lib/libz.so.1", "/usr/lib/libz.so.1.3.2"}, want: "/usr/lib/libz.so.1.3.3"},
		{name: "longest prefix wins", src: "/usr/lib/libm.so-2.44", srcs: []string{"/usr/lib/libm.so", "/usr/lib/libm.so.6", "/usr/lib/libm.so-2.44"}, want: "/usr/lib/libm.so-2.45"},
		{name: "no other source is a prefix", src: "/usr/lib/libz.so.1.3.2", srcs: []string{"/usr/lib/libz.so.1.3.2"}},
		{name: "two candidates", src: "/usr/lib/libq.so.5.0", srcs: []string{"/usr/lib/libq.so.5", "/usr/lib/libq.so.5.0"}},
		{name: "no candidate", src: "/usr/lib/libx.so.1.0", srcs: []string{"/usr/lib/libx.so.1", "/usr/lib/libx.so.1.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := renamed(files, tt.srcs, tt.src); got != tt.want {
				t.Errorf("renamed(%s) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// runEngine fakes the engine for apply: whether the image is in the store,
// how a run ends, and every run it was asked for.
type runEngine struct {
	container.Engine
	existsErr error
	runErr    error
	runs      []container.RunOpts
	code      int
}

func (e *runEngine) ImageExists(context.Context, string) (bool, error) { return true, e.existsErr }

func (e *runEngine) ContainerRun(_ context.Context, opts container.RunOpts) (int, error) {
	e.runs = append(e.runs, opts)
	return e.code, e.runErr
}

func TestApply(t *testing.T) {
	goImage := primitive.NewImageRef("registry.example.com/go@" + unknown)
	tests := []struct {
		engine  *runEngine
		files   map[string][]byte
		name    string
		wantErr string
		runs    int
	}{
		{name: "writes, then runs both commands", engine: &runEngine{}, files: map[string][]byte{"lane.cue": []byte("new")}, runs: 2},
		{name: "image not in the store", engine: &runEngine{existsErr: errors.New("store down")}, wantErr: "store down"},
		{name: "engine fails the run", engine: &runEngine{runErr: errors.New("no engine")}, wantErr: "go get -u -t go@1.2.3 ./... tool: no engine", runs: 1},
		{name: "command fails", engine: &runEngine{code: 1}, wantErr: "go get -u -t go@1.2.3 ./... tool: exit status 1", runs: 1},
		{name: "file cannot be written", engine: &runEngine{}, files: map[string][]byte{"absent/lane.cue": nil}, wantErr: "absent/lane.cue"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "lane.cue"), []byte("old"), 0o600); err != nil {
				t.Fatalf("seed: %v", err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatalf("open root: %v", err)
			}
			defer testutil.CloseLog(t, root, "root")
			err = apply(context.Background(), root, tt.engine, tt.files, goImage, "1.2.3")
			if tt.wantErr == "" && err != nil {
				t.Fatalf("apply: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("apply error = %v, want it to contain %q", err, tt.wantErr)
			}
			if len(tt.engine.runs) != tt.runs {
				t.Fatalf("runs = %d, want %d", len(tt.engine.runs), tt.runs)
			}
			if tt.runs != 2 {
				return
			}
			if got, readErr := root.ReadFile("lane.cue"); readErr != nil || string(got) != "new" {
				t.Errorf("lane.cue = %q, %v, want new", got, readErr)
			}
			tidy := tt.engine.runs[1]
			if !slices.Equal(tidy.Cmd, []string{"mod", "tidy"}) || tidy.Image != goImage || tidy.Workdir != dir {
				t.Errorf("second run = %v in %s of %s, want mod tidy in %s of %s", tidy.Cmd, tidy.Workdir, tidy.Image, dir, goImage)
			}
			if len(tidy.Mounts) != 1 || tidy.Mounts[0].Source != dir || tidy.Mounts[0].Target != dir || tidy.Mounts[0].ReadOnly {
				t.Errorf("mounts = %v, want the tree writable at its own path", tidy.Mounts)
			}
			if tidy.Env["GOTOOLCHAIN"] != "local" || tidy.Env["GOMODCACHE"] != tidy.Volume.Dest {
				t.Errorf("env = %v with the module cache at %s, want the local toolchain and that cache", tidy.Env, tidy.Volume.Dest)
			}
		})
	}
}
