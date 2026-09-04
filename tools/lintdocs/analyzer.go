// lintdocs gates the two tree-wide source checks that need no Go type
// information: every non-test Markdown, Go, CUE and SVG file in the module
// tree is printable ASCII, and every ADR file on disk is referenced from the
// ADR index. Both checks walk the module tree from the directory holding
// go.mod rather than the packages the driver loaded, because most of the
// covered files sit in directories that hold no Go package at all. A finding
// is reported at a synthesized position inside the offending file, so the
// diagnostic names that file rather than a Go package.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/tools/go/analysis"
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

// ASCIIAnalyzer reports source files that hold a byte outside printable ASCII.
var ASCIIAnalyzer = &analysis.Analyzer{
	Name: "asciionly",
	Doc:  "report non-ASCII bytes in Markdown, Go, CUE and SVG source files",
	Run:  runASCII,
}

// ADRIndexAnalyzer reports an ADR file that the ADR index does not reference.
var ADRIndexAnalyzer = &analysis.Analyzer{
	Name: "adrindex",
	Doc:  "report ADR files the ADR index does not reference",
	Run:  runADRIndex,
}

// Each check covers the whole module tree, so it runs on the first pass that
// reaches it and is a no-op on every later one: the driver calls an analyzer
// once per loaded package.
var (
	asciiOnce sync.Once
	adrOnce   sync.Once
)

// moduleTree memoizes the opened module root. os.Root makes a path that would
// leave the tree impossible to open rather than merely audited
// (docs/CODE-STYLE.md#path-confined-io). The root stays open for the life of
// the process: every pass after the first reuses it.
var moduleTree struct {
	once sync.Once
	root *os.Root
	err  error
}

func runASCII(pass *analysis.Pass) (any, error) {
	var err error
	asciiOnce.Do(func() { err = walkASCII(pass) })
	return nil, err
}

func runADRIndex(pass *analysis.Pass) (any, error) {
	var err error
	adrOnce.Do(func() { err = checkADRIndex(pass) })
	return nil, err
}

// moduleRoot opens the directory holding go.mod, found by walking up from the
// working directory, so the checks cover the module tree regardless of the
// directory the driver was started in. Every read below goes through the
// returned root.
func moduleRoot() (*os.Root, error) {
	moduleTree.once.Do(func() {
		dir, err := os.Getwd()
		if err != nil {
			moduleTree.err = err
			return
		}
		for {
			if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
				moduleTree.root, moduleTree.err = os.OpenRoot(dir)
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				moduleTree.err = fmt.Errorf("go.mod not found above working directory")
				return
			}
			dir = parent
		}
	})
	return moduleTree.root, moduleTree.err
}

// walkASCII scans every covered file under the module root. Only .git is
// skipped: it holds no covered file, while other dot-directories do.
func walkASCII(pass *analysis.Pass) error {
	root, err := moduleRoot()
	if err != nil {
		return err
	}
	return fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, walkErr error) error {
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
		return scanASCII(pass, root, name)
	})
}

// scanASCII reports one diagnostic per line of name that holds a non-ASCII
// byte, positioned at the first such byte on that line. name is relative to
// the module root and is what the diagnostic shows.
func scanASCII(pass *analysis.Pass, root *os.Root, name string) error {
	content, err := fs.ReadFile(root.FS(), name)
	if err != nil {
		return err
	}
	offsets := nonASCIIOffsets(content)
	if len(offsets) == 0 {
		return nil
	}
	file := pass.Fset.AddFile(name, -1, len(content))
	file.SetLinesForContent(content)
	for _, off := range offsets {
		pass.Report(analysis.Diagnostic{Pos: file.Pos(off), Message: nonASCIIMessage})
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

// checkADRIndex reports every ADR file in the ADR directory whose name the
// index does not mention.
func checkADRIndex(pass *analysis.Pass) error {
	root, err := moduleRoot()
	if err != nil {
		return err
	}
	index, err := fs.ReadFile(root.FS(), path.Join(adrDir, adrIndexName))
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(root.FS(), adrDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !isADRFile(name) || strings.Contains(string(index), name) {
			continue
		}
		if reportErr := reportMissingADR(pass, root, path.Join(adrDir, name), name); reportErr != nil {
			return reportErr
		}
	}
	return nil
}

// reportMissingADR reports the missing index entry at the start of the ADR
// file itself. rel is relative to the module root; name is the bare file name
// the message quotes.
func reportMissingADR(pass *analysis.Pass, root *os.Root, rel, name string) error {
	content, err := fs.ReadFile(root.FS(), rel)
	if err != nil {
		return err
	}
	file := pass.Fset.AddFile(rel, -1, len(content))
	file.SetLinesForContent(content)
	pass.Report(analysis.Diagnostic{
		Pos:     file.Pos(0),
		Message: fmt.Sprintf("ADR on disk but missing from %s: %s", adrIndexName, name),
	})
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
