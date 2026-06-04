package executor

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// flattenImageToFS reads the flattened root filesystem of img fully into
// memory and returns an immutable, in-memory fs.FS over it. No filesystem is
// touched, so there is nothing to clean up and no unpack/read race. Files
// expose io.ReaderAt so the go-buildinfo source can hand the file straight to
// debug/buildinfo.Read without copying it whole.
func flattenImageToFS(img v1.Image) (fs.FS, error) {
	rc := mutate.Extract(img)
	defer closer.Warn(rc, "flatten extract")

	buf, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("read flattened image: %w", err)
	}

	dirs := make(map[string]*memDir)
	dirs["."] = &memDir{name: "."}

	r := bytes.NewReader(buf)
	tr := tar.NewReader(r)
	for {
		hdr, tarErr := tr.Next()
		if tarErr == io.EOF {
			break
		}
		if tarErr != nil {
			return nil, fmt.Errorf("read tar entry: %w", tarErr)
		}

		clean := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if clean == "." {
			continue
		}

		ensureParents(dirs, clean)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if _, exists := dirs[clean]; !exists {
				dirs[clean] = &memDir{
					name: path.Base(clean),
					mode: hdr.FileInfo().Mode(),
				}
			}
			parent := path.Dir(clean)
			dirs[parent].addChild(clean)

		case tar.TypeReg:
			// After Next(), the reader is positioned at the content start.
			contentOff := int64(len(buf)) - int64(r.Len())
			entry := &memFile{
				buf:  buf,
				name: path.Base(clean),
				off:  contentOff,
				size: hdr.Size,
				mode: hdr.FileInfo().Mode(),
			}
			parent := path.Dir(clean)
			d := dirs[parent]
			if d.files == nil {
				d.files = make(map[string]*memFile)
			}
			d.files[clean] = entry
			d.addChild(clean)

		default:
			// Symlinks, hardlinks, devices are not materialized.
			continue
		}
	}

	return &memFS{dirs: dirs}, nil
}

// ensureParents creates directory entries for all ancestors of p.
func ensureParents(dirs map[string]*memDir, p string) {
	dir := path.Dir(p)
	if dir == "." {
		return
	}
	if _, exists := dirs[dir]; !exists {
		ensureParents(dirs, dir)
		dirs[dir] = &memDir{
			name: path.Base(dir),
			mode: fs.ModeDir | 0o755,
		}
		parent := path.Dir(dir)
		dirs[parent].addChild(dir)
	}
}

// memFS is an in-memory fs.FS backed by a single []byte slice.
type memFS struct {
	dirs map[string]*memDir
}

// Open implements fs.FS.
func (m *memFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if d, ok := m.dirs[name]; ok {
		return &memDirFile{dir: d, dirs: m.dirs}, nil
	}
	parent := path.Dir(name)
	if d, ok := m.dirs[parent]; ok {
		if f, ok := d.files[name]; ok {
			return f.open(), nil
		}
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

// memDir represents a directory in the in-memory filesystem.
type memDir struct {
	name     string
	files    map[string]*memFile
	children []string // full paths of children (dirs and files), sorted
	mode     fs.FileMode
}

func (d *memDir) addChild(fullPath string) {
	for _, c := range d.children {
		if c == fullPath {
			return
		}
	}
	d.children = append(d.children, fullPath)
	sort.Strings(d.children)
}

// memFile represents a regular file backed by a slice of the tar buffer.
type memFile struct {
	name string
	buf  []byte
	off  int64
	size int64
	mode fs.FileMode
}

func (f *memFile) open() fs.File {
	sr := io.NewSectionReader(bytes.NewReader(f.buf), f.off, f.size)
	return &memOpenFile{file: f, sr: sr}
}

// memOpenFile is an open file handle implementing fs.File and io.ReaderAt.
type memOpenFile struct {
	file *memFile
	sr   *io.SectionReader
}

// Read implements io.Reader.
func (f *memOpenFile) Read(p []byte) (int, error) { return f.sr.Read(p) }

// ReadAt implements io.ReaderAt.
func (f *memOpenFile) ReadAt(p []byte, off int64) (int, error) { return f.sr.ReadAt(p, off) }

// Stat implements fs.File.
func (f *memOpenFile) Stat() (fs.FileInfo, error) {
	return memFileInfo{name: f.file.name, size: f.file.size, mode: f.file.mode}, nil
}

// Close implements fs.File.
func (f *memOpenFile) Close() error { return nil }

// memDirFile is an open directory handle implementing fs.File and fs.ReadDirFile.
type memDirFile struct {
	dir  *memDir
	dirs map[string]*memDir
	pos  int
}

// Read implements fs.File (directories cannot be read).
func (d *memDirFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.dir.name, Err: fmt.Errorf("is a directory")}
}

// Stat implements fs.File.
func (d *memDirFile) Stat() (fs.FileInfo, error) {
	return memFileInfo{name: d.dir.name, mode: d.dir.mode | fs.ModeDir, isDir: true}, nil
}

// Close implements fs.File.
func (d *memDirFile) Close() error { return nil }

// ReadDir implements fs.ReadDirFile.
func (d *memDirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	children := d.dir.children
	if d.pos >= len(children) {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}

	end := len(children)
	if n > 0 && d.pos+n < end {
		end = d.pos + n
	}

	var entries []fs.DirEntry
	for _, child := range children[d.pos:end] {
		if subDir, ok := d.dirs[child]; ok {
			if subDir.files == nil || subDir.files[child] == nil {
				entries = append(entries, memDirEntry{
					name:  path.Base(child),
					mode:  subDir.mode | fs.ModeDir,
					isDir: true,
				})
				continue
			}
		}
		parent := path.Dir(child)
		if pd, ok := d.dirs[parent]; ok {
			if f, ok := pd.files[child]; ok {
				entries = append(entries, memDirEntry{
					name: path.Base(child),
					mode: f.mode,
					size: f.size,
				})
			}
		}
	}
	d.pos = end
	if n > 0 && d.pos >= len(children) {
		return entries, io.EOF
	}
	return entries, nil
}

// memFileInfo implements fs.FileInfo.
type memFileInfo struct {
	name  string
	size  int64
	mode  fs.FileMode
	isDir bool
}

func (i memFileInfo) Name() string        { return i.name }
func (i memFileInfo) Size() int64         { return i.size }
func (i memFileInfo) Mode() fs.FileMode   { return i.mode }
func (i memFileInfo) ModTime() clock.Time { return clock.Time{} }
func (i memFileInfo) IsDir() bool         { return i.isDir }
func (i memFileInfo) Sys() any            { return nil }

// memDirEntry implements fs.DirEntry.
type memDirEntry struct {
	name  string
	size  int64
	mode  fs.FileMode
	isDir bool
}

func (e memDirEntry) Name() string      { return e.name }
func (e memDirEntry) IsDir() bool       { return e.isDir }
func (e memDirEntry) Type() fs.FileMode { return e.mode.Type() }

func (e memDirEntry) Info() (fs.FileInfo, error) {
	return memFileInfo(e), nil
}
