package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
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

// hardLink marks the content of a tarLayer entry as a hard link to the entry
// named after it.
const hardLink = "hardlink:"

// tarLayer returns an uncompressed layer of files, keyed by the name the
// layer gives them. A name that ends in a slash is a directory, and content
// that starts with hardLink makes a hard link.
func tarLayer(t *testing.T, files map[string]string) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		content := files[name]
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if strings.HasSuffix(name, "/") {
			hdr.Typeflag = tar.TypeDir
		}
		if target, ok := strings.CutPrefix(content, hardLink); ok {
			hdr = &tar.Header{Name: name, Mode: 0o644, Linkname: target, Typeflag: tar.TypeLink}
			content = ""
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
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

// planned runs plan over tree, with every configure applied to the upgrader
// first, and returns the files it would write as text.
func planned(t *testing.T, ns string, tree fstest.MapFS, version string, configure ...func(*upgrader)) (map[string]string, primitive.ImageRef, error) {
	t.Helper()
	u := newUpgrader(context.Background(), ns)
	for _, c := range configure {
		c(u)
	}
	files, goImage, err := u.plan(tree, version)
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
	for name := range pinnedByHand {
		tree[name] = &fstest.MapFile{Data: stale}
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
		wantErr []string
	}{
		{
			name:    "present paths stay",
			sources: "/usr/lib/go /usr/lib/libz.so.1",
		},
		{
			name:    "missing paths are all reported",
			sources: "/usr/bin/gone /usr/lib/libz.so.1 /usr/lib/libq.so.5",
			wantErr: []string{"a/Containerfile:1: ", "go has no /usr/bin/gone", "go has no /usr/lib/libq.so.5"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := testNamespace(t, nil)
			_, oldManifest := push(t, ns+"go:latest", goRoot(map[string]string{"old": ""}))
			_, newManifest := push(t, ns+"go:latest", goRoot(map[string]string{"usr/lib/libz.so.1": ""}))
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
			want := "COPY --from=" + ns + "go@" + newManifest + " " + tt.sources + " /usr/lib/\n"
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

// layerBytes returns the uncompressed tar of files, as tarLayer builds it.
func layerBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	rc, err := tarLayer(t, files).Uncompressed()
	if err != nil {
		t.Fatalf("layer: %v", err)
	}
	whole, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("layer: %v", err)
	}
	return whole
}

func TestPlanFailsOnTheRegistry(t *testing.T) {
	whole := layerBytes(t, map[string]string{versionPath: "const version = `go1.2.3`"})
	exe := layerBytes(t, map[string]string{"usr/bin/x": elfExecutable(t, "/lib/ld.so", "libc.so.6")})
	tests := []struct {
		refuse *refusal
		layer  v1.Layer
		name   string
		tree   string
	}{
		{name: "no go image", tree: "lane.cue"},
		{name: "layer is no archive", tree: "lane.cue", layer: static.NewLayer([]byte("no archive"), types.OCIUncompressedLayer)},
		{name: "version file is cut short", tree: "lane.cue", layer: static.NewLayer(whole[:520], types.OCIUncompressedLayer)},
		{name: "executable is cut short in its magic", tree: "lane.cue", layer: static.NewLayer(exe[:514], types.OCIUncompressedLayer)},
		{name: "executable is cut short after its magic", tree: "lane.cue", layer: static.NewLayer(exe[:530], types.OCIUncompressedLayer)},
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

// tool returns a Go tool pin as the tree writes it. The pins of these tests
// are assembled by it, so that this file holds none the command follows.
func tool(pkg, version string) string {
	return pkg + "@" + version
}

// elfExecutable returns a minimal little-endian ELF64 file whose dynamic
// section needs libs. With interp it names that program interpreter, as a
// dynamically linked executable does; without it is a shared library.
func elfExecutable(t *testing.T, interp string, libs ...string) string {
	t.Helper()
	dynstr := "\x00"
	var dyn []elf.Dyn64
	for _, lib := range libs {
		dyn = append(dyn, elf.Dyn64{Tag: int64(elf.DT_NEEDED), Val: uint64(len(dynstr))})
		dynstr += lib + "\x00"
	}
	dyn = append(dyn, elf.Dyn64{Tag: int64(elf.DT_NULL)})
	const shstrtab = "\x00.dynstr\x00.dynamic\x00.shstrtab\x00"
	var progs []elf.Prog64
	var phnum uint16
	interpData := ""
	if interp != "" {
		interpData = interp + "\x00"
		progs = append(progs, elf.Prog64{Type: uint32(elf.PT_INTERP), Off: 64 + 56, Filesz: uint64(len(interpData)), Memsz: uint64(len(interpData)), Align: 1})
		phnum = 1
	}
	dynstrOff := 64 + 56*uint64(phnum) + uint64(len(interpData))
	dynOff := dynstrOff + uint64(len(dynstr))
	shstrOff := dynOff + uint64(16*len(dyn))
	hdr := elf.Header64{
		Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Shoff: shstrOff + uint64(len(shstrtab)), Ehsize: 64, Phentsize: 56, Phnum: phnum,
		Shentsize: 64, Shnum: 4, Shstrndx: 3,
	}
	if phnum > 0 {
		hdr.Phoff = 64
	}
	copy(hdr.Ident[:], elf.ELFMAG)
	hdr.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	hdr.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	hdr.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	sections := []elf.Section64{
		{},
		{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: dynstrOff, Size: uint64(len(dynstr)), Addralign: 1},
		{Name: 9, Type: uint32(elf.SHT_DYNAMIC), Off: dynOff, Size: uint64(16 * len(dyn)), Link: 1, Addralign: 8, Entsize: 16},
		{Name: 18, Type: uint32(elf.SHT_STRTAB), Off: shstrOff, Size: uint64(len(shstrtab)), Addralign: 1},
	}
	var buf bytes.Buffer
	for _, part := range []any{hdr, progs, []byte(interpData + dynstr), dyn, []byte(shstrtab), sections} {
		if err := binary.Write(&buf, binary.LittleEndian, part); err != nil {
			t.Fatalf("elf: %v", err)
		}
	}
	return buf.String()
}

// captured makes the log print into a buffer and returns a function that
// restores the log's output and returns what it printed meanwhile.
func captured(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	restore := func() { log.SetOutput(prev) }
	t.Cleanup(restore)
	return func() string {
		restore()
		return buf.String()
	}
}

// sources serves the Go module proxy, the npm registry and the GitHub API of
// a test, under the base URL it returns, from the documents build returns
// for that base, keyed by path. It returns the configuration that points an
// upgrader at it. A path without a document answers 404, and a document
// "500" answers 500.
func sources(t *testing.T, build func(base string) map[string]string) (configure func(*upgrader), base string) {
	t.Helper()
	var documents map[string]string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		document, ok := documents[r.URL.Path]
		switch {
		case !ok:
			http.NotFound(w, r)
		case document == "500":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			if _, err := io.WriteString(w, document); err != nil {
				t.Errorf("serve %s: %v", r.URL.Path, err)
			}
		}
	}))
	base = "http://" + srv.Listener.Addr().String()
	documents = build(base)
	srv.Start()
	t.Cleanup(srv.Close)
	return func(u *upgrader) {
		u.goProxy = base + "/proxy/"
		u.npm = base + "/npm/"
		u.githubWeb = base + "/dl/"
		u.githubAPI = base + "/api/"
	}, base
}

func TestPlanMovesToolPins(t *testing.T) {
	ns := testNamespace(t, nil)
	push(t, ns+"go:latest", goRoot(nil))
	configure, _ := sources(t, func(string) map[string]string {
		return map[string]string{
			"/proxy/example.com/lint/v2/@latest": `{"Version":"v2.1.0"}`,
			"/proxy/example.com/vuln/@latest":    `{"Version":"v1.0.0"}`,
			"/proxy/example.com/pre/@latest":     `{"Version":"v1.0.0"}`,
		}
	})
	lint := tool("example.com/lint/v2/cmd/lint", "v2.0.0")
	makefile := "lint:\n\tgo run " + lint + " ./...\n" +
		"vuln:\n\tgo run " + tool("example.com/vuln/cmd/vuln", "v1.0.0") + "\n" +
		"pre:\n\tgo run " + tool("example.com/pre", "v1.1.0-rc.1") + "\n"
	containerfile := `RUN ["go", "install", "` + lint + `"]` + "\n"
	tree := fstest.MapFS{"Makefile": {Data: []byte(makefile)}, "a/Containerfile": {Data: []byte(containerfile)}}
	got, _, err := planned(t, ns, tree, "1.2.3", configure)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	moved := tool("example.com/lint/v2/cmd/lint", "v2.1.0")
	want := map[string]string{
		"Makefile":        strings.Replace(makefile, lint, moved, 1),
		"a/Containerfile": strings.Replace(containerfile, lint, moved, 1),
	}
	if !maps.Equal(got, want) {
		t.Errorf("planned files = %v, want %v", got, want)
	}
}

func TestPlanMovesDownloads(t *testing.T) {
	ns := testNamespace(t, nil)
	push(t, ns+"go:latest", goRoot(nil))
	tarball := "the new package"
	sum256, sum512 := sha256.Sum256([]byte(tarball)), sha512.Sum512([]byte(tarball))
	asset := strings.Repeat("b", 64)
	configure, base := sources(t, func(base string) map[string]string {
		return map[string]string{
			"/npm/@acme/cli/latest":                  `{"dist":{"tarball":"` + base + `/npm/@acme/cli/-/cli-1.1.0.tgz","integrity":"sha512-` + base64.StdEncoding.EncodeToString(sum512[:]) + `"}}`,
			"/npm/@acme/cli/-/cli-1.1.0.tgz":         tarball,
			"/npm/stay/latest":                       `{"dist":{"tarball":"` + base + `/npm/stay/-/stay-1.0.0.tgz"}}`,
			"/api/acme/tool/releases/latest":         `{"tag_name":"v2","assets":[{"name":"other"},{"name":"tool-linux","digest":"sha256:` + asset + `"}]}`,
			"/api/acme/same/releases/latest":         `{"tag_name":"v1"}`,
			"/api/containers/podman/releases/latest": "500",
		}
	})
	npm, web := base+"/npm/", base+"/dl/"
	old := "ADD --checksum=sha256:" + strings.Repeat("a", 64)
	lines := []string{
		old + " " + npm + "@acme/cli/-/cli-1.0.0.tgz /tmp/cli.tgz\n",
		old + " " + npm + "stay/-/stay-1.0.0.tgz /tmp/stay.tgz\n",
		old + " --chmod=755 " + web + "acme/tool/releases/download/v1/tool-linux /usr/bin/tool\n",
		old + " " + web + "acme/same/releases/download/v1/same /usr/bin/same\n",
		old + " " + web + "containers/podman/releases/download/v5.4.2/podman.tgz /tmp/podman.tgz\n",
		old + " https://example.com/file /tmp/file\n",
	}
	containerfile := strings.Join(lines, "")
	got, _, err := planned(t, ns, fstest.MapFS{"Containerfile": {Data: []byte(containerfile)}}, "1.2.3", configure)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	lines[0] = "ADD --checksum=sha256:" + hex.EncodeToString(sum256[:]) + " " + npm + "@acme/cli/-/cli-1.1.0.tgz /tmp/cli.tgz\n"
	lines[2] = "ADD --checksum=sha256:" + asset + " --chmod=755 " + web + "acme/tool/releases/download/v2/tool-linux /usr/bin/tool\n"
	if want := strings.Join(lines, ""); got["Containerfile"] != want {
		t.Errorf("Containerfile =\n%s\nwant\n%s", got["Containerfile"], want)
	}
}

func TestPlanFailsOnTheReleaseSources(t *testing.T) {
	add := "ADD --checksum=sha256:" + strings.Repeat("a", 64) + " "
	tests := []struct {
		documents map[string]string
		name      string
		file      string
		line      string
		want      string
		offline   bool
	}{
		{name: "proxy fails", file: "Makefile", line: tool("example.com/x/cmd/x", "v1.0.0"), documents: map[string]string{"/proxy/example.com/x/cmd/x/@latest": "500"}, want: "500 Internal Server Error"},
		{name: "no module", file: "Makefile", line: tool("example.com/none/cmd/x", "v1.0.0"), want: "no module on"},
		{name: "malformed module path", file: "Makefile", line: tool("example.com/bad./cmd", "v1.0.0"), want: "malformed module path"},
		{name: "proxy answers no JSON", file: "Makefile", line: tool("example.com/x", "v1.0.0"), documents: map[string]string{"/proxy/example.com/x/@latest": "no JSON"}, want: "invalid character"},
		{name: "source unreachable", file: "Makefile", line: tool("example.com/x", "v1.0.0"), offline: true, want: "offline"},
		{name: "npm package without latest", file: "Containerfile", line: add + "{base}/npm/gone/-/gone-1.tgz /x", want: "has no latest version"},
		{name: "npm URL is no tarball", file: "Containerfile", line: add + "{base}/npm/p.tgz /x", want: "is no npm package tarball"},
		{name: "npm tarball outside the package", file: "Containerfile", line: add + "{base}/npm/p/-/p-1.tgz /x", documents: map[string]string{"/npm/p/latest": `{"dist":{"tarball":"{base}/npm/q/-/q-2.tgz"}}`}, want: "outside the package"},
		{name: "npm states no sha512", file: "Containerfile", line: add + "{base}/npm/p/-/p-1.tgz /x", documents: map[string]string{"/npm/p/latest": `{"dist":{"tarball":"{base}/npm/p/-/p-2.tgz","integrity":"sha1-AAAA"}}`}, want: "states no sha512"},
		{name: "npm tarball does not match", file: "Containerfile", line: add + "{base}/npm/p/-/p-1.tgz /x", documents: map[string]string{"/npm/p/latest": `{"dist":{"tarball":"{base}/npm/p/-/p-2.tgz","integrity":"sha512-AAAA"}}`, "/npm/p/-/p-2.tgz": "other bytes"}, want: "does not match the integrity"},
		{name: "npm tarball not served", file: "Containerfile", line: add + "{base}/npm/p/-/p-1.tgz /x", documents: map[string]string{"/npm/p/latest": `{"dist":{"tarball":"{base}/npm/p/-/p-2.tgz","integrity":"sha512-AAAA"}}`}, want: "404 Not Found"},
		{name: "npm tarball URL is malformed", file: "Containerfile", line: add + "{base}/npm/p/-/p-1.tgz /x", documents: map[string]string{"/npm/p/latest": `{"dist":{"tarball":"{base}/npm/p/-/p%zz.tgz","integrity":"sha512-AAAA"}}`}, want: "invalid URL escape"},
		{name: "GitHub URL is no release asset", file: "Containerfile", line: add + "{base}/dl/acme/tool/archive/v1.tgz /x", want: "is no GitHub release asset"},
		{name: "GitHub repository without release", file: "Containerfile", line: add + "{base}/dl/acme/tool/releases/download/v1/t /x", want: "has no latest release"},
		{name: "GitHub release without the asset", file: "Containerfile", line: add + "{base}/dl/acme/tool/releases/download/v1/t /x", documents: map[string]string{"/api/acme/tool/releases/latest": `{"tag_name":"v2","assets":[]}`}, want: "acme/tool v2 has no asset t"},
		{name: "GitHub publishes no sha256", file: "Containerfile", line: add + "{base}/dl/acme/tool/releases/download/v1/t /x", documents: map[string]string{"/api/acme/tool/releases/latest": `{"tag_name":"v2","assets":[{"name":"t"}]}`}, want: "acme/tool v2 publishes no sha256 for t"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := testNamespace(t, nil)
			push(t, ns+"go:latest", goRoot(nil))
			configure, base := sources(t, func(base string) map[string]string {
				documents := map[string]string{}
				for p, document := range tt.documents {
					documents[p] = strings.ReplaceAll(document, "{base}", base)
				}
				return documents
			})
			offline := func(u *upgrader) {
				if tt.offline {
					u.get = func(string) (*http.Response, error) { return nil, errors.New("offline") }
				}
			}
			tree := fstest.MapFS{tt.file: {Data: []byte(strings.ReplaceAll(tt.line, "{base}", base) + "\n")}}
			_, _, err := planned(t, ns, tree, "1.2.3", configure, offline)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("plan error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestPlanFlagsDynamicExecutables(t *testing.T) {
	ns := testNamespace(t, nil)
	push(t, ns+"go:latest", goRoot(nil))
	_, oldGit := push(t, ns+"git:latest", map[string]string{"old": ""})
	push(t, ns+"git:latest", map[string]string{
		"usr/bin/git":                     elfExecutable(t, "/lib/ld.so", "libz.so.1", "libpcre2-8.so.0", "libc.so.6"),
		"usr/lib/libz.so.1":               elfExecutable(t, "", "libzstd.so.1"),
		"usr/lib/libc.so.6":               elfExecutable(t, "/lib/ld.so", "ld.so"),
		"usr/libexec/git-core/":           "",
		"usr/libexec/git-core/git":        hardLink + "usr/bin/git",
		"usr/libexec/git-core/git-remote": elfExecutable(t, "/lib/ld.so", "libcurl.so.4", "libc.so.6"),
		"usr/libexec/git-core/git-sh":     "#!/bin/sh\n",
		"usr/libexec/git-core/broken":     "\x7fELF, and nothing an ELF parser reads",
		"usr/libexec/git-core/short":      "ab",
	})
	output := captured(t)
	tree := fstest.MapFS{"Containerfile": {Data: []byte(
		"COPY --from=" + ns + "git@" + oldGit + " /usr/bin/git /usr/lib/libz.so.1 /usr/lib/libc.so.6 /usr/libexec/git-core /usr/\n" +
			"COPY --from=loader /lib/ld.so /lib/\n")}}
	if _, _, err := planned(t, ns, tree, "1.2.3"); err != nil {
		t.Fatalf("plan: %v", err)
	}
	var got []string
	for _, line := range strings.SplitAfter(output(), "\n") {
		if i := strings.Index(line, "Containerfile:"); i >= 0 && strings.Contains(line, " needs ") {
			got = append(got, line[i:])
		}
	}
	want := []string{
		"Containerfile:1: /usr/bin/git needs libpcre2-8.so.0, which no COPY in this file copies\n",
		"Containerfile:1: /usr/libexec/git-core/git needs libpcre2-8.so.0, which no COPY in this file copies\n",
		"Containerfile:1: /usr/libexec/git-core/git-remote needs libcurl.so.4, which no COPY in this file copies\n",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("flags = %q, want %q", got, want)
	}
}
