// Package regtest provides OCI image fixtures and a standalone tar extractor
// for registry-adjacent tests. It uses only public go-containerregistry and
// standard-library APIs and is imported solely by test files, so it is never
// linked into the strike binary -- keeping test-only helpers out of the
// production artifact.
package regtest

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/primitive"
	"github.com/istr/strike/internal/registry"
	"github.com/istr/strike/internal/testutil"
)

// Registry returns an in-memory OCI registry for tests. With referrersAPI it
// serves the referrers API and reports each listed referrer's artifactType by
// the OCI distribution rule -- the manifest's own artifactType, else its
// config media type -- where go-containerregistry's test registry reads the
// config media type only. Without referrersAPI the referrers endpoint answers
// 404, the shape of a registry that does not implement the API.
func Registry(t *testing.T, referrersAPI bool) http.Handler {
	t.Helper()
	inner := ggcrregistry.New(ggcrregistry.WithReferrersSupport(referrersAPI))
	if !referrersAPI {
		return inner
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elems := strings.Split(r.URL.Path, "/")
		if r.Method != http.MethodGet || len(elems) < 5 || elems[len(elems)-2] != "referrers" {
			inner.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		inner.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			testutil.WriteBody(t, w, rec.Body.Bytes())
			return
		}
		var idx v1.IndexManifest
		if err := json.Unmarshal(rec.Body.Bytes(), &idx); err != nil {
			t.Errorf("decode referrers index: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		repo := strings.Join(elems[2:len(elems)-2], "/")
		for i := range idx.Manifests {
			idx.Manifests[i].ArtifactType = referrerArtifactType(t, inner, r, repo, idx.Manifests[i].Digest)
		}
		w.Header().Set("Content-Type", string(types.OCIImageIndex))
		testutil.WriteJSON(t, w, idx)
	})
}

// referrerArtifactType reads one referrer manifest from inner and returns its
// artifact type by the OCI distribution rule.
func referrerArtifactType(t *testing.T, inner http.Handler, r *http.Request, repo string, digest v1.Hash) string {
	t.Helper()
	req := r.Clone(r.Context())
	req.URL.Path = "/v2/" + repo + "/manifests/" + digest.String()
	req.URL.RawQuery = ""
	rec := httptest.NewRecorder()
	inner.ServeHTTP(rec, req)
	var m v1.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Errorf("decode referrer manifest %s: %v", digest, err)
		return ""
	}
	if m.ArtifactType != "" {
		return m.ArtifactType
	}
	return string(m.Config.MediaType)
}

// BuildImageTar builds a deterministic single-layer OCI image layout tar
// containing exactly one file, and returns the tar bytes and the manifest
// digest. Replaces the former registry.BuildTestImageTar.
func BuildImageTar(fileName string, content []byte) ([]byte, primitive.Digest, error) {
	layer, err := singleFileLayer(fileName, content)
	if err != nil {
		return nil, "", err
	}

	img := mutate.ConfigMediaType(
		mutate.MediaType(empty.Image, types.OCIManifestSchema1),
		types.OCIConfigJSON,
	)
	img, err = mutate.AppendLayers(img, layer)
	if err != nil {
		return nil, "", err
	}
	annotated, ok := mutate.Annotations(img, map[string]string{
		"org.opencontainers.image.created": "1970-01-01T00:00:00Z",
	}).(v1.Image)
	if !ok {
		return nil, "", fmt.Errorf("annotate: unexpected image type")
	}
	img = annotated

	h, err := img.Digest()
	if err != nil {
		return nil, "", err
	}

	tarBytes, err := LayoutTar(img)
	if err != nil {
		return nil, "", err
	}
	return tarBytes, primitive.Digest(h.String()), nil
}

// BuildMultiFileImageTar builds a deterministic single-layer OCI image layout
// tar containing the given files, and returns the tar bytes. Entries are
// written in iteration order; dirs must be created explicitly by the caller
// if needed (the layer is a flat name -> content map).
func BuildMultiFileImageTar(files map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Size:     int64(len(content)),
			Mode:     0o644,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(content); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}
	layer, err := tarball.LayerFromOpener(opener, tarball.WithMediaType(types.OCILayer))
	if err != nil {
		return nil, err
	}

	img := mutate.ConfigMediaType(
		mutate.MediaType(empty.Image, types.OCIManifestSchema1),
		types.OCIConfigJSON,
	)
	img, err = mutate.AppendLayers(img, layer)
	if err != nil {
		return nil, err
	}
	annotated, ok := mutate.Annotations(img, map[string]string{
		"org.opencontainers.image.created": "1970-01-01T00:00:00Z",
	}).(v1.Image)
	if !ok {
		return nil, fmt.Errorf("annotate: unexpected image type")
	}
	return LayoutTar(annotated)
}

// BuildLayeredImageTar builds a deterministic OCI image layout tar with one
// content layer carrying the given files, stamped with outputID under
// registry.OutputLayerAnnotation. It returns the layout tar and the layer's
// uncompressed-content digest (diff_id) -- the stable engine-level selection
// key (ADR-046), which the consumer passes to SeedTarFromImage.
func BuildLayeredImageTar(outputID string, files map[string][]byte) ([]byte, primitive.Digest, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		content := files[name]
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Size:     int64(len(content)),
			Mode:     0o644,
		}); err != nil {
			return nil, "", err
		}
		if _, err := tw.Write(content); err != nil {
			return nil, "", err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, "", err
	}
	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}
	layer, err := tarball.LayerFromOpener(opener, tarball.WithMediaType(types.OCILayer))
	if err != nil {
		return nil, "", err
	}
	diffID, err := layer.DiffID()
	if err != nil {
		return nil, "", err
	}

	img := mutate.ConfigMediaType(
		mutate.MediaType(empty.Image, types.OCIManifestSchema1),
		types.OCIConfigJSON,
	)
	img, err = mutate.Append(img, mutate.Addendum{
		Layer:       layer,
		Annotations: map[string]string{registry.OutputLayerAnnotation: outputID},
	})
	if err != nil {
		return nil, "", err
	}
	annotated, ok := mutate.Annotations(img, map[string]string{
		"org.opencontainers.image.created": "1970-01-01T00:00:00Z",
	}).(v1.Image)
	if !ok {
		return nil, "", fmt.Errorf("annotate: unexpected image type")
	}
	tarBytes, err := LayoutTar(annotated)
	if err != nil {
		return nil, "", err
	}
	return tarBytes, primitive.Digest(diffID.String()), nil
}

// singleFileLayer builds a deterministic OCI layer with one regular file.
func singleFileLayer(name string, content []byte) (v1.Layer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Size:     int64(len(content)),
		Mode:     0o644,
		// Uid, Gid, ModTime intentionally zero for determinism.
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(content); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}
	return tarball.LayerFromOpener(opener, tarball.WithMediaType(types.OCILayer))
}

// LayoutTar writes img as an OCI layout and returns the layout serialized as a
// tar. If annotations are provided, the first map is set on the index.
// Replaces the former registry.SingleImageTarForTest.
func LayoutTar(img v1.Image, annotations ...map[string]string) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "regtest-layout-")
	if err != nil {
		return nil, err
	}
	defer closer.Remove(tmpDir, "regtest layout")

	lp, err := layout.Write(tmpDir, empty.Index)
	if err != nil {
		return nil, err
	}
	var opts []layout.Option
	if len(annotations) > 0 && annotations[0] != nil {
		opts = append(opts, layout.WithAnnotations(annotations[0]))
	}
	if err := lp.AppendImage(img, opts...); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tarDir(tmpDir, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ExtractTar extracts an OCI layout tar (directories and regular files) into
// root. It is a STANDALONE test utility built on the standard library, NOT a
// wrapper around any production extraction helper -- production extraction
// stays covered by the ExtractSingleLayer tests. Replaces the former
// registry.ExtractTarForTest, whose only use is unpacking a layout tar to
// inspect it (e.g. to recover a manifest digest).
func ExtractTar(data []byte, root *os.Root) error {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !filepath.IsLocal(hdr.Name) {
			return fmt.Errorf("tar entry %q is not a local path", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if mkErr := root.MkdirAll(hdr.Name, 0o750); mkErr != nil {
				return mkErr
			}
		case tar.TypeReg:
			if wErr := writeRegular(root, hdr.Name, tr); wErr != nil {
				return wErr
			}
		default:
			return fmt.Errorf("tar entry %q has unsupported type %d", hdr.Name, hdr.Typeflag)
		}
	}
}

// writeRegular writes one regular-file entry into root, creating parents.
func writeRegular(root *os.Root, name string, r io.Reader) (err error) {
	if dir := filepath.Dir(name); dir != "." {
		if mkErr := root.MkdirAll(dir, 0o750); mkErr != nil {
			return mkErr
		}
	}
	f, err := root.Create(name)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	_, err = io.Copy(f, r)
	return err
}

// tarDir writes dir as a tar archive to w, in deterministic fs.WalkDir order.
func tarDir(dir string, w io.Writer) (err error) {
	tw := tar.NewWriter(w)
	defer func() {
		if cerr := tw.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	root := os.DirFS(dir)
	return fs.WalkDir(root, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		hdr, hdrErr := tar.FileInfoHeader(info, "")
		if hdrErr != nil {
			return hdrErr
		}
		hdr.Name = path
		if d.IsDir() {
			hdr.Name += "/"
		}
		if whErr := tw.WriteHeader(hdr); whErr != nil {
			return whErr
		}
		if d.IsDir() {
			return nil
		}
		f, openErr := root.Open(path)
		if openErr != nil {
			return openErr
		}
		defer closer.Warn(f, "regtest tar dir")
		_, cpErr := io.Copy(tw, f)
		return cpErr
	})
}
