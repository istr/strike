// lintfrom fails when code outside internal/lane reads the .From field
// on lane.InputRef, lane.PackFile, or lane.ArtifactRef.
// After lane.Build, resolved edges are the only valid consumer API.
//
// imageFromStep is deliberately not guarded: it is a bare step-id string that
// names a producing step, not a {step, output} ref that needs parsing the way
// inp.From did. Consumers should still prefer dag.ImageFromEdges, but a direct
// read of step.ImageFromStep is not unsafe.
package main

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"strings"

	"golang.org/x/tools/go/packages"
)

var forbiddenTypes = map[string]bool{
	"github.com/istr/strike/internal/lane.InputRef":    true,
	"github.com/istr/strike/internal/lane.PackFile":    true,
	"github.com/istr/strike/internal/lane.ArtifactRef": true,
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: lintfrom <package-pattern>...")
		os.Exit(2)
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo,
	}
	pkgs, err := packages.Load(cfg, os.Args[1:]...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	failed := false
	for _, pkg := range pkgs {
		if strings.Contains(pkg.PkgPath, "/internal/lane") {
			continue
		}
		for _, f := range pkg.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "From" {
					return true
				}
				tv, ok := pkg.TypesInfo.Types[sel.X]
				if !ok {
					return true
				}
				t := tv.Type
				if ptr, ok := t.(*types.Pointer); ok {
					t = ptr.Elem()
				}
				if named, ok := t.(*types.Named); ok {
					full := named.Obj().Pkg().Path() + "." + named.Obj().Name()
					if forbiddenTypes[full] {
						pos := pkg.Fset.Position(sel.Pos())
						fmt.Fprintf(os.Stderr,
							"%s: read of .From on %s outside internal/lane; use resolved DAG edges\n",
							pos, full)
						failed = true
					}
				}
				return true
			})
		}
	}
	if failed {
		os.Exit(1)
	}
}
