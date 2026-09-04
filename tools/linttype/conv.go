package main

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// StutterAnalyzer reports a stuttering accessor x.<Noun>.<Noun>() whose
// receiver's named type is named differently from the accessor: the tell of a
// field named after a wire noun that carries a concept type projecting back
// through a same-named method. A value legitimately typed after its name (a URL
// field read as URL()) does not trip. See docs/ADR-048-contract-type-semantics.md.
var StutterAnalyzer = &analysis.Analyzer{
	Name:     "linttypestutter",
	Doc:      "report stuttering accessors whose receiver type name differs from the accessor",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      runStutter,
}

func runStutter(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	insp.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call := n.(*ast.CallExpr)
		if len(call.Args) != 0 {
			return
		}
		outer, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}
		if calleeName(outer.X) != outer.Sel.Name {
			return
		}
		t := pass.TypesInfo.TypeOf(outer.X)
		if ptr, ok := t.(*types.Pointer); ok {
			t = ptr.Elem()
		}
		named, ok := t.(*types.Named)
		if !ok || named.Obj().Name() == outer.Sel.Name {
			return
		}
		pass.Reportf(outer.Sel.Pos(),
			"stuttering accessor %s.%s(): value typed %s named after wire noun %q; rename the concept side",
			outer.Sel.Name, outer.Sel.Name, named.Obj().Name(), outer.Sel.Name)
	})
	return nil, nil
}

// ownsConversion reports whether pkgPath is the defining package of any strike
// named type involved in the conversion -- where its methods, and therefore
// its conversions, legitimately live. A type's external test package
// (<pkg>_test) is the same ownership layer for that package's own test code, so
// it is treated as own-package too.
func ownsConversion(pkgPath string, target, source *types.Named) bool {
	for _, named := range [2]*types.Named{target, source} {
		if named == nil {
			continue
		}
		defPath := named.Obj().Pkg().Path()
		if pkgPath == defPath || pkgPath == defPath+"_test" {
			return true
		}
	}
	return false
}

// calleeName renders an expression as a bare identifier: an *ast.Ident's name
// or an *ast.SelectorExpr's selector name, and the empty string otherwise. It
// serves both an outer call's Fun and a selector receiver.
func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}
