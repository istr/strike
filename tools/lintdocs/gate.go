package main

import (
	"fmt"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
)

// asciiExts are the file extensions the ASCII gate covers. A file whose name
// ends in _test.go is out of scope.
var asciiExts = map[string]bool{".md": true, ".go": true, ".cue": true, ".svg": true}

const (
	// adrDir holds the ADR files and the index that must reference them.
	adrDir = "docs"

	// adrIndexName is the index every ADR file must appear in.
	adrIndexName = "ADR-INDEX.md"

	// adrPrefix starts the name of every ADR file; a digit must follow it.
	adrPrefix = "ADR-"

	nonASCIIMessage = "non-ASCII byte in source file"
)

// gate accumulates findings against one file set, so every position renders as
// file:line:column against the content it was measured in.
type gate struct {
	root  *os.Root
	fset  *token.FileSet
	found []string
}

// file registers content under name, so a byte offset in it can be rendered as
// a line and a column.
func (g *gate) file(name string, content []byte) *token.File {
	f := g.fset.AddFile(name, -1, len(content))
	f.SetLinesForContent(content)
	return f
}

// report records one finding at a byte offset in a registered file.
func (g *gate) report(f *token.File, off int, msg string) {
	g.found = append(g.found, fmt.Sprintf("%s: %s", g.fset.Position(f.Pos(off)), msg))
}

// moduleRoot opens the directory holding go.mod, found by walking up from the
// working directory, so the checks cover the module tree regardless of the
// directory the command was started in. os.Root makes a path that would leave
// the tree impossible to open rather than merely audited
// (docs/CODE-STYLE.md#path-confined-io). The root stays open for the life of
// the process, which walks the tree once and exits.
func moduleRoot() (*os.Root, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return os.OpenRoot(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, fmt.Errorf("go.mod not found above working directory")
		}
		dir = parent
	}
}

// walkASCII scans every covered file under the module root. Only .git is
// skipped: it holds no covered file, while other dot-directories do.
func (g *gate) walkASCII() error {
	return fs.WalkDir(g.root.FS(), ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		base := d.Name()
		if strings.HasSuffix(base, "_test.go") || !asciiExts[path.Ext(base)] {
			return nil
		}
		return g.scanASCII(name)
	})
}

// scanASCII records one finding per line of name that holds a non-ASCII byte,
// positioned at the first such byte on that line. name is relative to the
// module root and is what the finding shows.
func (g *gate) scanASCII(name string) error {
	content, err := fs.ReadFile(g.root.FS(), name)
	if err != nil {
		return err
	}
	offsets := nonASCIIOffsets(content)
	if len(offsets) == 0 {
		return nil
	}
	file := g.file(name, content)
	for _, off := range offsets {
		g.report(file, off, nonASCIIMessage)
	}
	return nil
}

// nonASCIIOffsets returns the byte offset of the first non-ASCII rune on every
// line of content that holds one.
func nonASCIIOffsets(content []byte) []int {
	var offsets []int
	base := 0
	for _, line := range strings.SplitAfter(string(content), "\n") {
		if i := strings.IndexFunc(line, func(r rune) bool { return r > unicode.MaxASCII }); i >= 0 {
			offsets = append(offsets, base+i)
		}
		base += len(line)
	}
	return offsets
}

// checkADRIndex records every ADR file in the ADR directory whose name the
// index does not mention.
func (g *gate) checkADRIndex() error {
	fsys := g.root.FS()
	index, err := fs.ReadFile(fsys, path.Join(adrDir, adrIndexName))
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(fsys, adrDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !isADRFile(name) || strings.Contains(string(index), name) {
			continue
		}
		if reportErr := g.reportMissingADR(path.Join(adrDir, name), name); reportErr != nil {
			return reportErr
		}
	}
	return nil
}

// reportMissingADR records the missing index entry at the start of the ADR file
// itself. rel is relative to the module root; name is the bare file name the
// message quotes.
func (g *gate) reportMissingADR(rel, name string) error {
	content, err := fs.ReadFile(g.root.FS(), rel)
	if err != nil {
		return err
	}
	g.report(g.file(rel, content), 0,
		fmt.Sprintf("ADR on disk but missing from %s: %s", adrIndexName, name))
	return nil
}

// isADRFile reports whether name is an ADR file the index must cover: the ADR
// prefix, a digit, and the Markdown extension. The index itself does not match.
func isADRFile(name string) bool {
	if !strings.HasPrefix(name, adrPrefix) || !strings.HasSuffix(name, ".md") {
		return false
	}
	rest := name[len(adrPrefix):]
	return rest != "" && rest[0] >= '0' && rest[0] <= '9'
}
