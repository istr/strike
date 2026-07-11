// linttypeconv fails the build on any conversion of a strike named type
// sitting directly in a call argument, except within that type's own defining
// package or a site named in the central allowlist.
//
// CUE gives these types their structure; Go adds behavior, and a type
// conversion is behavior, so it is owned in one place: the type's own package,
// through its methods. A conversion anywhere else scatters the boundary across
// callers. The same string(id) is fine as a named assignment, a
// composite-literal field, a method body, or a bare return, and is a defect
// only as a call argument -- a distinction a text match cannot draw.
package main

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const strikePrefix = "github.com/istr/strike/"

// allow lists conversion sites intentionally left untyped, with the reason.
// An entry exempts conversions whose enclosing call has the given callee name
// in the given package. Remove an entry when its conversion is typed away; an
// empty allowlist means the tree is exhaustively type-clean.
var allow = []struct{ pkg, callee, reason string }{
	{
		pkg:    "github.com/istr/strike/internal/mediator",
		callee: "canonicalize",
		reason: "peer host canonicalization is typed when the resolver path is reworked",
	},
}

// Analyzer reports a strike named-type conversion used directly as a call
// argument, outside the type's own package and the central allowlist.
var Analyzer = &analysis.Analyzer{
	Name:     "linttypeconv",
	Doc:      "report conversions of strike named types used directly as call arguments",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

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

func run(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	insp.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		outer := n.(*ast.CallExpr)
		for _, arg := range outer.Args {
			conv, ok := arg.(*ast.CallExpr)
			if !ok || len(conv.Args) != 1 {
				continue
			}
			tv, ok := pass.TypesInfo.Types[conv.Fun]
			if !ok || !tv.IsType() {
				continue
			}
			target := strikeNamed(pass.TypesInfo.TypeOf(conv.Fun))
			source := strikeNamed(pass.TypesInfo.TypeOf(conv.Args[0]))
			named := target
			if named == nil {
				named = source
			}
			if named == nil {
				continue
			}
			if ownsConversion(pass.Pkg.Path(), target, source) {
				continue
			}
			if allowed(pass.Pkg.Path(), calleeName(outer.Fun)) {
				continue
			}
			pass.Reportf(conv.Pos(),
				"conversion of %s in a call argument; type the source or own the conversion in %s",
				named.Obj().Name(), named.Obj().Pkg().Path())
		}
	})
	return nil, nil
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

// strikeNamed returns t as a strike-defined *types.Named (after unwrapping a
// pointer), or nil when t is not a named type defined under the strike module.
func strikeNamed(t types.Type) *types.Named {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return nil
	}
	obj := named.Obj()
	if obj.Pkg() == nil {
		return nil
	}
	if !strings.HasPrefix(obj.Pkg().Path(), strikePrefix) {
		return nil
	}
	return named
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

// allowed reports whether (pkgPath, callee) names a deferred site.
func allowed(pkgPath, callee string) bool {
	for _, a := range allow {
		if a.pkg == pkgPath && a.callee == callee {
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
