// Command upgrade moves the module to a Go release together with everything
// the tree pins beside the toolchain. It takes the release as its argument and
// does three things:
//
//   - every cgr.dev/chainguard image reference in a Containerfile, a Go file
//     or a CUE file, outside the files pinnedByHand names, moves to the image
//     its repository's tag names now, each in the form it already has: an
//     index digest stays an index digest, a manifest digest becomes the
//     linux/amd64 manifest of the new index;
//   - every path a Containerfile copies out of a moved image is checked
//     against the layers of that image, and a file that only changed its
//     version suffix is renamed in place;
//   - go get and go mod tidy run in a container from the new Go image with
//     the module tree mounted, and move the go directive and every module
//     requirement.
//
// The Go image is the toolchain, so the command fails before it changes
// anything when that image does not state the requested release, and likewise
// when a copied path is gone and no rename is unambiguous. It starts no
// process: the registry is read over HTTPS and the go commands run through
// the engine API. With -n it prints what would change and touches neither the
// tree nor the engine.
//
// Afterwards the dev container still carries the old toolchain: rebuild it,
// then run make check.
package main

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"maps"
	"net/http"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/container"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/testutil"
)

const (
	// namespace starts every image reference the command follows.
	namespace = "cgr.dev/chainguard/"

	// goRepository is the repository whose image is the Go toolchain.
	goRepository = "go"

	// versionFile is where a built Go root states its own release.
	versionFile = "/usr/lib/go/src/internal/buildcfg/zbootstrap.go"

	// moduleCache is the engine volume the go commands download into. The
	// race sibling of make test reads the same volume, so the gate that
	// follows an upgrade downloads nothing again.
	moduleCache = "strike-race-gomod"
)

// tags names the tag a repository's references follow where that is not
// latest. A digest does not record the tag it was read from.
var tags = map[string]string{"python": "latest-dev"}

// pinnedByHand names the files whose references only the operator moves. A
// test fixture there must stay an image no other pin names, and following its
// tag would make it the image another pin of the repository names as well.
var pinnedByHand = map[string]bool{"cmd/strike/materialize_integration_test.go": true}

// statedVersion matches the release in the content of versionFile.
var statedVersion = regexp.MustCompile("const version = `go([0-9.]+)`")

// image is what the tag of one repository names now.
type image struct {
	content  v1.Image
	files    map[string]bool
	version  string
	index    string
	manifest string
}

// upgrader plans one upgrade. It reads the registry once per repository and
// once per pinned digest, and collects every finding instead of stopping at
// the first, so one run shows all that has to be settled by hand.
type upgrader struct {
	images     map[string]*image
	successors map[string]string
	pin        *regexp.Regexp
	namespace  string
	opts       []remote.Option
	findings   []string
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("upgrade: ")
	args := os.Args[1:]
	dry := len(args) > 0 && args[0] == "-n"
	if dry {
		args = args[1:]
	}
	if len(args) != 1 {
		log.Fatal("usage: upgrade [-n] <go-version>")
	}
	if err := run(context.Background(), args[0], dry); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, version string, dry bool) error {
	dir, err := testutil.ModuleRoot()
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer closer.Warn(root, "module root")
	files, goImage, err := newUpgrader(ctx, namespace).plan(root.FS(), version)
	if err != nil {
		return err
	}
	if dry {
		log.Print("nothing written")
		return nil
	}
	// The engine reports its platform before anything is written, so an
	// engine that is not there leaves the tree as it was.
	engine, err := container.New()
	if err != nil {
		return err
	}
	if err = engine.Info(ctx); err != nil {
		return err
	}
	if err = apply(ctx, root, engine, files, goImage, version); err != nil {
		return err
	}
	log.Print("rebuild the dev container, then run make check")
	return nil
}

// newUpgrader returns an upgrader that follows the references starting with
// ns and reads linux/amd64 wherever a tag names an index.
func newUpgrader(ctx context.Context, ns string) *upgrader {
	return &upgrader{
		images:     map[string]*image{},
		successors: map[string]string{},
		pin:        regexp.MustCompile(regexp.QuoteMeta(ns) + `([a-z0-9-]+)@(sha256:[0-9a-f]{64})`),
		namespace:  ns,
		opts: []remote.Option{
			remote.WithContext(ctx),
			remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}),
		},
	}
}

// plan reads the tree and the registry and writes nothing. It returns the new
// content of every file that changes and the reference of the Go image the go
// commands run in. It fails when the Go image does not state version and when
// a Containerfile copies a path a moved image no longer has.
func (u *upgrader) plan(tree fs.FS, version string) (map[string][]byte, primitive.ImageRef, error) {
	goImage, err := u.image(goRepository)
	if err != nil {
		return nil, "", err
	}
	if err = goImage.read(); err != nil {
		return nil, "", err
	}
	carried := "no stated release"
	if m := statedVersion.FindStringSubmatch(goImage.version); m != nil {
		carried = "go " + m[1]
	}
	if carried != "go "+version {
		return nil, "", fmt.Errorf("%s%s carries %s, not go %s", u.namespace, goRepository, carried, version)
	}
	files := map[string][]byte{}
	err = fs.WalkDir(tree, ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return skipDir(tree, name)
		}
		if base := d.Name(); base != "Containerfile" && path.Ext(base) != ".go" && path.Ext(base) != ".cue" {
			return nil
		}
		content, readErr := fs.ReadFile(tree, name)
		if readErr != nil {
			return readErr
		}
		next, rewriteErr := u.rewrite(name, string(content))
		if rewriteErr == nil && next != string(content) {
			files[name] = []byte(next)
		}
		return rewriteErr
	})
	if err != nil {
		return nil, "", err
	}
	if len(u.findings) > 0 {
		return nil, "", errors.New(strings.Join(u.findings, "\n"))
	}
	return files, primitive.NewImageRef(u.namespace + goRepository + "@" + goImage.manifest), nil
}

// skipDir keeps the walk out of .git and out of a checkout nested in the
// tree, which is a module of its own with its own pins.
func skipDir(tree fs.FS, name string) error {
	if path.Base(name) == ".git" {
		return fs.SkipDir
	}
	if _, err := fs.Stat(tree, path.Join(name, "go.mod")); err == nil && name != "." {
		return fs.SkipDir
	}
	return nil
}

// rewrite returns content with every followed reference moved to its
// successor. In a Containerfile it first checks the sources of every COPY
// that reads from a reference that moves. A file pinned by hand comes back
// as it is.
func (u *upgrader) rewrite(name, content string) (string, error) {
	if pinnedByHand[name] {
		return content, nil
	}
	for _, m := range u.pin.FindAllStringSubmatch(content, -1) {
		if err := u.follow(m[0], m[1], m[2]); err != nil {
			return "", err
		}
	}
	if path.Base(name) == "Containerfile" {
		lines := strings.SplitAfter(content, "\n")
		for i := range lines {
			checked, err := u.checkCopy(fmt.Sprintf("%s:%d", name, i+1), lines[i])
			if err != nil {
				return "", err
			}
			lines[i] = checked
		}
		content = strings.Join(lines, "")
	}
	return u.pin.ReplaceAllStringFunc(content, func(ref string) string {
		if next := u.successors[ref]; next != "" {
			return ref[:strings.Index(ref, "@")+1] + next
		}
		return ref
	}), nil
}

// follow records the digest that replaces the one ref pins: the digest of the
// tag for an index, the linux/amd64 manifest for a manifest. A digest the
// registry does not know is a fixture, not a pin, and is left as written.
func (u *upgrader) follow(ref, repo, digest string) error {
	if _, done := u.successors[ref]; done {
		return nil
	}
	pinned, err := name.NewDigest(ref)
	if err != nil {
		return err
	}
	head, err := remote.Head(pinned, u.opts...)
	var status *transport.Error
	if errors.As(err, &status) && status.StatusCode == http.StatusNotFound {
		u.successors[ref] = ""
		log.Printf("%s: not in the registry, left as written", ref)
		return nil
	}
	if err != nil {
		return err
	}
	img, err := u.image(repo)
	if err != nil {
		return err
	}
	next := img.manifest
	if head.MediaType.IsIndex() {
		next = img.index
	}
	if next == digest {
		next = ""
	} else {
		log.Printf("%s -> %s", ref, next)
	}
	u.successors[ref] = next
	return nil
}

// image resolves the tag of repo: the digest the tag names, and the digest of
// its linux/amd64 manifest, which is the same one when the tag names a single
// image.
func (u *upgrader) image(repo string) (*image, error) {
	if img, ok := u.images[repo]; ok {
		return img, nil
	}
	tag := tags[repo]
	if tag == "" {
		tag = "latest"
	}
	ref, err := name.ParseReference(u.namespace + repo + ":" + tag)
	if err != nil {
		return nil, err
	}
	desc, err := remote.Get(ref, u.opts...)
	if err != nil {
		return nil, err
	}
	content, err := desc.Image()
	if err != nil {
		return nil, err
	}
	manifest, err := content.Digest()
	if err != nil {
		return nil, err
	}
	img := &image{content: content, index: desc.Digest.String(), manifest: manifest.String()}
	u.images[repo] = img
	return img, nil
}

// read lists every path in the layers of the image and keeps the content of
// versionFile. A second call reads nothing.
func (i *image) read() error {
	if i.files != nil {
		return nil
	}
	layers, err := i.content.Layers()
	if err != nil {
		return err
	}
	i.files = map[string]bool{}
	for _, layer := range layers {
		if err = i.readLayer(layer); err != nil {
			return err
		}
	}
	return nil
}

func (i *image) readLayer(layer v1.Layer) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return err
	}
	defer closer.Warn(rc, "image layer")
	tr := tar.NewReader(rc)
	for {
		h, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			return nil
		}
		if nextErr != nil {
			return nextErr
		}
		name := path.Clean("/" + h.Name)
		i.files[name] = true
		if name != versionFile {
			continue
		}
		stated, readErr := io.ReadAll(tr)
		if readErr != nil {
			return readErr
		}
		i.version = string(stated)
	}
}

// checkCopy checks one Containerfile line. A COPY that reads from a reference
// that moves must name only paths its new image has. A missing path that
// renamed finds a successor for is replaced in the returned line; any other
// is a finding at pos.
func (u *upgrader) checkCopy(pos, line string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 || !strings.EqualFold(fields[0], "COPY") {
		return line, nil
	}
	var from string
	var srcs []string
	for _, field := range fields[1 : len(fields)-1] {
		if ref, ok := strings.CutPrefix(field, "--from="); ok {
			from = ref
		} else if !strings.HasPrefix(field, "--") {
			srcs = append(srcs, field)
		}
	}
	m := u.pin.FindStringSubmatch(from)
	if m == nil || m[0] != from || u.successors[from] == "" {
		return line, nil
	}
	img := u.images[m[1]]
	if err := img.read(); err != nil {
		return "", err
	}
	for _, src := range srcs {
		if img.files[src] {
			continue
		}
		to := renamed(img.files, srcs, src)
		if to == "" {
			u.findings = append(u.findings, fmt.Sprintf("%s: %s%s has no %s", pos, u.namespace, m[1], src))
			continue
		}
		log.Printf("%s: %s -> %s", pos, src, to)
		line = strings.Replace(line, " "+src+" ", " "+to+" ", 1)
	}
	return line, nil
}

// renamed returns the path that took the place of src, a COPY source its
// image no longer has, or "" when there is not exactly one. A library is
// copied under its soname and under its full version, libz.so.1 and
// libz.so.1.3.2, and a patch release keeps the first and renames the second.
// So the candidates are the files beside src whose name starts with the
// longest other source that is a prefix of src, without the sources
// themselves.
func renamed(files map[string]bool, srcs []string, src string) string {
	stem := ""
	for _, other := range srcs {
		if other != src && strings.HasPrefix(src, other) && len(other) > len(stem) {
			stem = other
		}
	}
	if stem == "" {
		return ""
	}
	found := ""
	for file := range files {
		if !strings.HasPrefix(file, stem) || path.Dir(file) != path.Dir(src) || slices.Contains(srcs, file) {
			continue
		}
		if found != "" {
			return ""
		}
		found = file
	}
	return found
}

// apply writes the planned files and then runs the go commands. The commands
// come last because they move the go directive, and from then on the old
// toolchain of the dev container refuses the module, this command included.
func apply(ctx context.Context, root *os.Root, engine container.Engine, files map[string][]byte, goImage primitive.ImageRef, version string) error {
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if err := root.WriteFile(name, files[name], 0o600); err != nil {
			return err
		}
		log.Printf("wrote %s", name)
	}
	client := registry.Client{Engine: engine}
	if err := client.EnsureImage(ctx, goImage, registry.SystemTransports{}); err != nil {
		return err
	}
	dir := root.Name()
	for _, args := range [][]string{{"get", "-u", "-t", "go@" + version, "./...", "tool"}, {"mod", "tidy"}} {
		code, err := engine.ContainerRun(ctx, container.RunOpts{
			Image:           goImage,
			Cmd:             args,
			Workdir:         dir,
			Mounts:          []container.Mount{{Source: dir, Target: dir}},
			Volume:          &container.VolumeMount{Name: moduleCache, Dest: "/gomod"},
			Env:             map[string]string{"GOTOOLCHAIN": "local", "GOMODCACHE": "/gomod"},
			CapDrop:         []string{"ALL"},
			NoNewPrivileges: true,
			Remove:          true,
			Stdout:          log.Writer(),
			Stderr:          log.Writer(),
		})
		if err != nil {
			return fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
		}
		if code != 0 {
			return fmt.Errorf("go %s: exit status %d", strings.Join(args, " "), code)
		}
	}
	return nil
}
