// Command upgrade moves the module to a Go release together with everything
// the tree pins beside the toolchain. It takes the release as its argument and
// does five things:
//
//   - every cgr.dev/chainguard image reference in a Containerfile, a Makefile,
//     a Go file or a CUE file, outside the files pinnedByHand names, moves to
//     the image its repository's tag names now, each in the form it already
//     has: an index digest stays an index digest, a manifest digest becomes
//     the linux/amd64 manifest of the new index;
//   - every path a Containerfile copies out of a moved image is checked
//     against the layers of that image, a file that only changed its version
//     suffix is renamed in place, and every dynamically linked binary the
//     copy carries is named with each library it needs that no COPY of the
//     Containerfile copies;
//   - every Go tool those files pin as package path and module version moves
//     to the latest release of its module on the Go module proxy;
//   - every download a Containerfile pins with ADD --checksum moves to the
//     latest release of its npm package or GitHub repository, under the
//     checksum the source publishes for it, outside the repositories
//     heldReleases names;
//   - go get and go mod tidy run in a container from the new Go image with
//     the module tree mounted, and move the go directive and every module
//     requirement.
//
// The Go image is the toolchain, so the command fails before it changes
// anything when that image does not state the requested release, and likewise
// when a copied path is gone and no rename is unambiguous, or when a download
// does not match what its source publishes. It starts no process: the
// registries and release sources are read over HTTPS and the go commands run
// through the engine API. With -n it prints what would change and touches
// neither the tree nor the engine.
//
// Afterwards the dev container still carries the old toolchain: rebuild it,
// then run make check.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

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

	// goProxy, npmRegistry, githubWeb and githubAPI are where the latest
	// release of a Go tool or a download is read.
	goProxy     = "https://proxy.golang.org/"
	npmRegistry = "https://registry.npmjs.org/"
	githubWeb   = "https://github.com/"
	githubAPI   = "https://api.github.com/repos/"

	// documentLimit bounds a JSON document read from a release source.
	documentLimit = 4 << 20
)

// tags names the tag a repository's references follow where that is not
// latest. A digest does not record the tag it was read from.
var tags = map[string]string{"python": "latest-dev"}

// pinnedByHand names the files whose references only the operator moves. A
// test fixture there must stay an image no other pin names, and following its
// tag would make it the image another pin of the repository names as well.
var pinnedByHand = map[string]bool{"cmd/strike/materialize_integration_test.go": true}

// heldReleases names the GitHub repositories whose downloads stay at their
// release. The podman client follows the version of the engine it talks to
// (ADR-055), not the newest release.
var heldReleases = map[string]bool{"containers/podman": true}

// walked names the files whose references the command follows, by name and
// by extension.
var walked = map[string]bool{"Containerfile": true, "Makefile": true, ".go": true, ".cue": true}

// statedVersion matches the release in the content of versionFile.
var statedVersion = regexp.MustCompile("const version = `go([0-9.]+)`")

// toolPin matches a Go tool installed or run by package path and module
// version.
var toolPin = regexp.MustCompile(`([a-z0-9.-]+\.[a-z]+(?:/[A-Za-z0-9._~-]+)+)@(v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)`)

// download matches a Containerfile ADD of a URL under a sha256 checksum,
// together with the flags between the checksum and the URL.
var download = regexp.MustCompile(`ADD --checksum=sha256:([0-9a-f]{64})((?: --[a-z]+=\S+)*) (\S+)`)

// image is what the tag of one repository names now.
type image struct {
	content  v1.Image
	files    map[string]bool
	dynamic  map[string][]string
	version  string
	index    string
	manifest string
}

// release is the download that replaces another and the sha256 its source
// publishes for it. The zero release leaves the download as written.
type release struct {
	url string
	sum string
}

// upgrader plans one upgrade. It reads the registry once per repository and
// once per pinned digest, and collects every finding instead of stopping at
// the first, so one run shows all that has to be settled by hand.
type upgrader struct {
	images     map[string]*image
	successors map[string]string
	downloads  map[string]release
	get        func(url string) (*http.Response, error)
	pin        *regexp.Regexp
	namespace  string
	goProxy    string
	npm        string
	githubWeb  string
	githubAPI  string
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
// ns, reads linux/amd64 wherever a tag names an index, and reads the public
// release sources.
func newUpgrader(ctx context.Context, ns string) *upgrader {
	return &upgrader{
		images:     map[string]*image{},
		successors: map[string]string{},
		downloads:  map[string]release{},
		get: func(url string) (*http.Response, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
			if err != nil {
				return nil, err
			}
			return http.DefaultClient.Do(req)
		},
		pin:       regexp.MustCompile(regexp.QuoteMeta(ns) + `([a-z0-9-]+)@(sha256:[0-9a-f]{64})`),
		namespace: ns,
		goProxy:   goProxy,
		npm:       npmRegistry,
		githubWeb: githubWeb,
		githubAPI: githubAPI,
		opts: []remote.Option{
			remote.WithContext(ctx),
			remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}),
		},
	}
}

// plan reads the tree, the registry and the release sources, and writes
// nothing. It returns the new content of every file that changes and the
// reference of the Go image the go commands run in. It fails when the Go
// image does not state version and when a Containerfile copies a path a moved
// image no longer has.
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
		if base := d.Name(); !walked[base] && !walked[path.Ext(base)] {
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

// rewrite returns content with every followed image reference, tool pin and
// download moved to its successor. In a Containerfile it first checks the
// sources of every COPY that reads from a reference that moves. A file pinned
// by hand comes back as it is.
func (u *upgrader) rewrite(name, content string) (string, error) {
	if pinnedByHand[name] {
		return content, nil
	}
	for _, m := range u.pin.FindAllStringSubmatch(content, -1) {
		if err := u.follow(m[0], m[1], m[2]); err != nil {
			return "", err
		}
	}
	for _, m := range toolPin.FindAllStringSubmatch(content, -1) {
		if err := u.followTool(m[0], m[1], m[2]); err != nil {
			return "", err
		}
	}
	if path.Base(name) == "Containerfile" {
		for _, m := range download.FindAllStringSubmatch(content, -1) {
			if err := u.followDownload(m[3]); err != nil {
				return "", err
			}
		}
		lines := strings.SplitAfter(content, "\n")
		copies := copiedNames(lines)
		for i := range lines {
			checked, err := u.checkCopy(fmt.Sprintf("%s:%d", name, i+1), lines[i], copies)
			if err != nil {
				return "", err
			}
			lines[i] = checked
		}
		content = download.ReplaceAllStringFunc(strings.Join(lines, ""), u.moveDownload)
	}
	return toolPin.ReplaceAllStringFunc(u.pin.ReplaceAllStringFunc(content, u.move), u.move), nil
}

// move returns a followed image reference or tool pin with its successor's
// digest or version, or as it is when it stays.
func (u *upgrader) move(ref string) string {
	if next := u.successors[ref]; next != "" {
		return ref[:strings.Index(ref, "@")+1] + next
	}
	return ref
}

// moveDownload returns a matched ADD line with the URL and checksum of the
// release that replaces its download, or as it is when it stays.
func (u *upgrader) moveDownload(add string) string {
	m := download.FindStringSubmatch(add)
	next := u.downloads[m[3]]
	if next.url == "" {
		return add
	}
	return "ADD --checksum=sha256:" + next.sum + m[2] + " " + next.url
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

// followTool records the latest release of the module that provides pkg as
// the version that replaces the one ref pins, when it is newer. The module is
// the longest prefix of pkg the Go module proxy knows.
func (u *upgrader) followTool(ref, pkg, version string) error {
	if _, done := u.successors[ref]; done {
		return nil
	}
	for p := pkg; strings.Contains(p, "/"); p = path.Dir(p) {
		escaped, err := module.EscapePath(p)
		if err != nil {
			return err
		}
		var latest struct{ Version string }
		found, err := u.getJSON(u.goProxy+escaped+"/@latest", &latest)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		next := ""
		if semver.Compare(latest.Version, version) > 0 {
			next = latest.Version
			log.Printf("%s -> %s", ref, next)
		}
		u.successors[ref] = next
		return nil
	}
	return fmt.Errorf("no module on %s provides %s", u.goProxy, pkg)
}

// followDownload records the release that replaces the download at url. A
// URL of no known release source is left as written.
func (u *upgrader) followDownload(url string) error {
	if _, done := u.downloads[url]; done {
		return nil
	}
	var next release
	var err error
	switch {
	case strings.HasPrefix(url, u.npm):
		next, err = u.npmRelease(url)
	case strings.HasPrefix(url, u.githubWeb):
		next, err = u.githubRelease(url)
	default:
		log.Printf("%s: no known release source, left as written", url)
	}
	if err != nil {
		return err
	}
	if next.url != "" {
		log.Printf("%s -> %s", url, next.url)
	}
	u.downloads[url] = next
	return nil
}

// npmRelease returns the latest version of the npm package whose tarball url
// is, under the sha256 of a tarball that matches the integrity the registry
// states for it.
func (u *upgrader) npmRelease(url string) (release, error) {
	pkg, _, ok := strings.Cut(strings.TrimPrefix(url, u.npm), "/-/")
	if !ok {
		return release{}, fmt.Errorf("%s is no npm package tarball", url)
	}
	var latest struct {
		Dist struct{ Tarball, Integrity string }
	}
	found, err := u.getJSON(u.npm+pkg+"/latest", &latest)
	if err != nil {
		return release{}, err
	}
	if !found {
		return release{}, fmt.Errorf("%s%s has no latest version", u.npm, pkg)
	}
	if latest.Dist.Tarball == url {
		return release{}, nil
	}
	if !strings.HasPrefix(latest.Dist.Tarball, u.npm+pkg+"/-/") {
		return release{}, fmt.Errorf("%s%s names a tarball outside the package: %s", u.npm, pkg, latest.Dist.Tarball)
	}
	sum, err := u.checksum(latest.Dist.Tarball, latest.Dist.Integrity)
	if err != nil {
		return release{}, err
	}
	return release{url: latest.Dist.Tarball, sum: sum}, nil
}

// checksum downloads url and returns its sha256 once its sha512 matches
// integrity, which has the form sha512-<base64>.
func (u *upgrader) checksum(url, integrity string) (string, error) {
	want, ok := strings.CutPrefix(integrity, "sha512-")
	if !ok {
		return "", fmt.Errorf("%s: the registry states no sha512 integrity", url)
	}
	resp, err := u.get(url)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close %s: %v", url, closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	sum256, sum512 := sha256.New(), sha512.New()
	if _, err = io.Copy(io.MultiWriter(sum256, sum512), resp.Body); err != nil {
		return "", err
	}
	if base64.StdEncoding.EncodeToString(sum512.Sum(nil)) != want {
		return "", fmt.Errorf("%s does not match the integrity the registry states", url)
	}
	return hex.EncodeToString(sum256.Sum(nil)), nil
}

// githubRelease returns the latest release of the GitHub repository an asset
// of which url downloads, under the sha256 GitHub publishes for the asset. A
// repository heldReleases names stays at its release. An asset the release
// lacks or publishes no sha256 for is a finding.
func (u *upgrader) githubRelease(url string) (release, error) {
	parts := strings.Split(strings.TrimPrefix(url, u.githubWeb), "/")
	if len(parts) != 6 || parts[2] != "releases" || parts[3] != "download" {
		return release{}, fmt.Errorf("%s is no GitHub release asset", url)
	}
	repo, tag, asset := parts[0]+"/"+parts[1], parts[4], parts[5]
	if heldReleases[repo] {
		log.Printf("%s: held at its release, left as written", url)
		return release{}, nil
	}
	var latest struct {
		TagName string `json:"tag_name"`
		Assets  []struct{ Name, Digest string }
	}
	found, err := u.getJSON(u.githubAPI+repo+"/releases/latest", &latest)
	if err != nil {
		return release{}, err
	}
	if !found {
		return release{}, fmt.Errorf("%s has no latest release", repo)
	}
	if latest.TagName == tag {
		return release{}, nil
	}
	for _, a := range latest.Assets {
		if a.Name != asset {
			continue
		}
		if sum, ok := strings.CutPrefix(a.Digest, "sha256:"); ok {
			return release{url: u.githubWeb + repo + "/releases/download/" + latest.TagName + "/" + asset, sum: sum}, nil
		}
		u.findings = append(u.findings, fmt.Sprintf("%s %s publishes no sha256 for %s", repo, latest.TagName, asset))
		return release{}, nil
	}
	u.findings = append(u.findings, fmt.Sprintf("%s %s has no asset %s", repo, latest.TagName, asset))
	return release{}, nil
}

// getJSON decodes the JSON document at url into v. It reports false, and no
// error, when the source answers that the document does not exist.
func (u *upgrader) getJSON(url string, v any) (bool, error) {
	resp, err := u.get(url)
	if err != nil {
		return false, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("WARN close %s: %v", url, closeErr)
		}
	}()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, json.NewDecoder(io.LimitReader(resp.Body, documentLimit)).Decode(v)
	case http.StatusNotFound, http.StatusGone:
		return false, nil
	default:
		return false, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
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

// read lists every path in the layers of the image, keeps the content of
// versionFile, and records the libraries of every dynamically linked
// executable. A second call reads nothing.
func (i *image) read() error {
	if i.files != nil {
		return nil
	}
	layers, err := i.content.Layers()
	if err != nil {
		return err
	}
	i.files = map[string]bool{}
	i.dynamic = map[string][]string{}
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
		var readErr error
		switch {
		case name == versionFile:
			var stated []byte
			stated, readErr = io.ReadAll(tr)
			i.version = string(stated)
		case h.Typeflag == tar.TypeLink:
			if libs, ok := i.dynamic[path.Clean("/"+h.Linkname)]; ok {
				i.dynamic[name] = libs
			}
		case h.Typeflag == tar.TypeReg && h.Size >= int64(len(elf.ELFMAG)):
			readErr = i.readELF(name, h.Size, tr)
		}
		if readErr != nil {
			return readErr
		}
	}
}

// readELF records the libraries the file at name needs when it is an ELF
// executable that names a program interpreter, which is what makes it
// dynamically linked. A file the ELF parser refuses is not recorded.
func (i *image) readELF(name string, size int64, r io.Reader) error {
	magic := make([]byte, len(elf.ELFMAG))
	if _, err := io.ReadFull(r, magic); err != nil {
		return err
	}
	if string(magic) != elf.ELFMAG {
		return nil
	}
	content := make([]byte, size)
	copy(content, magic)
	if _, err := io.ReadFull(r, content[len(magic):]); err != nil {
		return err
	}
	f, err := elf.NewFile(bytes.NewReader(content))
	if err == nil && slices.ContainsFunc(f.Progs, func(p *elf.Prog) bool { return p.Type == elf.PT_INTERP }) {
		if libs, libErr := f.ImportedLibraries(); libErr == nil {
			i.dynamic[name] = libs
		}
	}
	return nil
}

// copySources returns the image or stage a COPY line reads from and the paths
// it copies, or nothing for any other line.
func copySources(line string) (string, []string) {
	fields := strings.Fields(line)
	if len(fields) < 3 || !strings.EqualFold(fields[0], "COPY") {
		return "", nil
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
	return from, srcs
}

// copiedNames returns the base name of every path a COPY among lines copies.
func copiedNames(lines []string) map[string]bool {
	copies := map[string]bool{}
	for _, line := range lines {
		_, srcs := copySources(line)
		for _, src := range srcs {
			copies[path.Base(src)] = true
		}
	}
	return copies
}

// checkCopy checks one Containerfile line. A COPY that reads from a reference
// that moves must name only paths its new image has. copies holds the base
// name of every path a COPY of the file copies.
func (u *upgrader) checkCopy(pos, line string, copies map[string]bool) (string, error) {
	from, srcs := copySources(line)
	m := u.pin.FindStringSubmatch(from)
	if m == nil || m[0] != from || u.successors[from] == "" {
		return line, nil
	}
	img := u.images[m[1]]
	if err := img.read(); err != nil {
		return "", err
	}
	for _, src := range srcs {
		line = u.copySource(pos, line, m[1], img, srcs, src, copies)
	}
	return line, nil
}

// copySource checks the source src of the COPY line at pos against img, the
// new image of repo. A missing path that renamed finds a successor for is
// replaced in the returned line; any other is a finding. A dynamically linked
// executable the source is or holds is named with every library it needs
// whose name is not in copies, for a check after the rebuild: the command
// does not check which stage copies a library, nor that it is the one the
// executable loads.
func (u *upgrader) copySource(pos, line, repo string, img *image, srcs []string, src string, copies map[string]bool) string {
	copied := src
	if !img.files[src] {
		copied = renamed(img.files, srcs, src)
		if copied == "" {
			u.findings = append(u.findings, fmt.Sprintf("%s: %s%s has no %s", pos, u.namespace, repo, src))
			return line
		}
		log.Printf("%s: %s -> %s", pos, src, copied)
		line = strings.Replace(line, " "+src+" ", " "+copied+" ", 1)
	}
	for _, exe := range slices.Sorted(maps.Keys(img.dynamic)) {
		if exe != copied && !strings.HasPrefix(exe, copied+"/") {
			continue
		}
		var missing []string
		for _, lib := range img.dynamic[exe] {
			if !copies[lib] {
				missing = append(missing, lib)
			}
		}
		if len(missing) > 0 {
			log.Printf("%s: %s needs %s, which no COPY in this file copies", pos, exe, strings.Join(missing, ", "))
		}
	}
	return line
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
