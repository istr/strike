// Command lintdoc gates the two tree-wide source checks that need no Go type
// information: every non-test Markdown, Go, CUE and SVG file in the module
// tree is printable ASCII, and every ADR file on disk is referenced from the
// ADR index. Both checks walk the module tree from the directory holding
// go.mod, because most of the covered files sit in directories that hold no
// Go package at all.
//
// The command takes no arguments: what it checks is the module tree it is run
// in, not a package pattern. A finding is rendered as file:line:column against
// the offending file, so an editor can jump to it, and a non-empty finding set
// exits non-zero.
package main

import (
	"go/token"
	"log"
	"os"
)

func main() {
	log.SetFlags(0)
	root, err := moduleRoot()
	if err != nil {
		log.Fatal(err)
	}
	g := &gate{root: root, fset: token.NewFileSet()}
	if walkErr := g.walkASCII(); walkErr != nil {
		log.Fatal(walkErr)
	}
	if adrErr := g.checkADRIndex(); adrErr != nil {
		log.Fatal(adrErr)
	}
	for _, f := range g.found {
		log.Print(f)
	}
	if len(g.found) > 0 {
		os.Exit(1)
	}
}
