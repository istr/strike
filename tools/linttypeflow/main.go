// Command linttypeflow reports type-flow leaks that the type checker can see:
// a strike named value that is detyped and retyped, or returned as a plain
// string. It has two modes. The default mode gates: it fails when a covered
// flow class appears outside the owned allowlist, printing one finding per line
// on stderr and exiting non-zero. The -report mode emits the full type-flow
// survey as JSONL on stdout and always exits zero; prose reports render from
// that data. The gate needs a buildable tree, so it aborts when the package
// loader reports any error.
//
// The survey records these fact kinds; the gate covers only roundtrip-local
// and result-string-scalar, the near-zero-false-positive classes:
//
//   - conversion: every type conversion involving a strike-defined named type,
//     with syntactic context (call-arg, return, assign, map-index, binop, ...)
//   - roundtrip-nested: T(string(x)) / string(T(s)) directly nested
//   - roundtrip-local: v := string(x) ... T(v) (and inverse) within one function
//   - param-string-typed-in-body: func has a plain-string(ish) param that the
//     body converts to a strike named type (typing starts too late)
//   - param-detyped-in-body: func has a strike-typed param that the body
//     converts back to a basic type (typing breaks too early)
//   - param-string-scalar-name: plain-string param whose name suggests a
//     scalar semantic (host, digest, id, ...) -- raw candidates, unfiltered
//   - result-string-scalar: func result is plain string but a return statement
//     returns a detyped strike value
//   - map-string-key: every map type literal with a plain string key
//   - map-index-typed-source: index into a string-keyed map where the key
//     expression is built from strike-typed values
//   - retype-from-stringop: conversion to a strike named type whose argument
//     is a function call (Sprintf, TrimSuffix, ...) -- grammar rebuilt outside
//     the owning type
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const strikePrefix = "github.com/istr/strike/"

type Fact struct {
	Kind    string `json:"kind"`
	Pos     string `json:"pos"`
	Pkg     string `json:"pkg"`
	Func    string `json:"func,omitempty"`
	FuncSig string `json:"funcsig,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Context string `json:"context,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Snippet string `json:"snippet,omitempty"`
	IsGen   bool   `json:"isgen,omitempty"`
	IsTest  bool   `json:"istest,omitempty"`
}

var scalarName = regexp.MustCompile(`(?i)(host|port|digest|path|id$|ids$|name$|ref|refs$|authority|image|commit|sha|hash|url|uri|addr|fingerprint|issuer|subject|user|tag|duration|timestamp|secret)`)

type collector struct {
	facts    []Fact
	seen     map[string]bool
	fset     *token.FileSet
	repoRoot string
}

// allowEntry tolerates one covered flow class in one function until its owning
// roadmap item retypes it. A finding is matched on (pkg, func, kind); entries
// are not line-pinned, so they survive unrelated edits to the same file.
type allowEntry struct {
	pkg    string
	fn     string
	kind   string
	owner  string // roadmap item id that owns the cleanup
	reason string
}

// allow is intentionally empty: linttypeflow stands up red so the covered tree
// is proven clean class by class as the cleanup items land. The first point
// where every covered class passes at once is where this gate graduates from
// the standalone lint-typeflow target into the aggregate lint target.
var allow = []allowEntry{}

// gatingKinds are the near-zero-false-positive classes the gate enforces. The
// survey still records every kind; only these fail the build.
var gatingKinds = map[string]bool{
	"roundtrip-local":      true,
	"result-string-scalar": true,
}

func allowed(allow []allowEntry, pkg, fn, kind string) bool {
	for _, a := range allow {
		if a.pkg == pkg && a.fn == fn && a.kind == kind {
			return true
		}
	}
	return false
}

// gateFindings keeps the covered classes that must fail the build: it drops
// non-gating kinds, drops generated files (regenerated from CUE, not hand
// fixable), and drops allowlisted sites.
func gateFindings(facts []Fact, allow []allowEntry) []Fact {
	var out []Fact
	for _, f := range facts {
		if !gatingKinds[f.Kind] || f.IsGen {
			continue
		}
		if allowed(allow, f.Pkg, f.Func, f.Kind) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func gateMessage(f Fact) string {
	if f.Kind == "result-string-scalar" {
		return fmt.Sprintf("%s: %s: %s returned as plain string in %s; return the named type or convert at the call boundary",
			f.Pos, f.Kind, f.From, f.Func)
	}
	return fmt.Sprintf("%s: %s: %s detyped to %s and retyped in %s (%s); keep the value typed end to end",
		f.Pos, f.Kind, f.From, f.To, f.Func, f.Detail)
}

func main() {
	report := flag.Bool("report", false,
		"emit the full type-flow survey as JSONL on stdout instead of gating")
	flag.Parse()
	patterns := flag.Args()
	if len(patterns) == 0 {
		fmt.Fprintln(os.Stderr, "usage: linttypeflow [-report] <package-pattern>...")
		os.Exit(2)
	}
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	facts, err := collect(dir, patterns)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *report {
		enc := json.NewEncoder(os.Stdout)
		for _, f := range facts {
			enc.Encode(f)
		}
		fmt.Fprintf(os.Stderr, "facts: %d\n", len(facts))
		return
	}
	findings := gateFindings(facts, allow)
	for _, f := range findings {
		fmt.Fprintln(os.Stderr, gateMessage(f))
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
}

// collect loads the given patterns rooted at dir and returns every type-flow
// fact in the strike packages, sorted by kind then position. The tree must
// compile: a load error aborts, because facts from a half-typed tree are noise.
func collect(dir string, patterns []string) ([]Fact, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports,
		Dir:   absDir,
		Tests: true,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	if n := countLoadErrors(pkgs); n > 0 {
		return nil, fmt.Errorf(
			"tree does not compile: %d load error(s); the flow lint needs a buildable tree", n)
	}
	c := &collector{seen: map[string]bool{}, repoRoot: absDir}
	for _, pkg := range pkgs {
		if !strings.HasPrefix(pkg.PkgPath, strikePrefix) && pkg.PkgPath != "github.com/istr/strike" {
			continue
		}
		c.fset = pkg.Fset
		for _, file := range pkg.Syntax {
			fname := c.fset.Position(file.Pos()).Filename
			if !strings.HasPrefix(fname, c.repoRoot) {
				continue // cgo/generated outside tree
			}
			c.walkFile(pkg, file)
		}
	}
	sort.SliceStable(c.facts, func(i, j int) bool {
		if c.facts[i].Kind != c.facts[j].Kind {
			return c.facts[i].Kind < c.facts[j].Kind
		}
		return c.facts[i].Pos < c.facts[j].Pos
	})
	return c.facts, nil
}

func countLoadErrors(pkgs []*packages.Package) int {
	n := 0
	packages.Visit(pkgs, nil, func(p *packages.Package) { n += len(p.Errors) })
	return n
}

func (c *collector) emit(f Fact) {
	key := f.Kind + "|" + f.Pos + "|" + f.From + "|" + f.To + "|" + f.Detail
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.facts = append(c.facts, f)
}

func (c *collector) relPos(p token.Pos) (string, bool, bool) {
	pos := c.fset.Position(p)
	rel, err := filepath.Rel(c.repoRoot, pos.Filename)
	if err != nil {
		rel = pos.Filename
	}
	isGen := strings.HasSuffix(pos.Filename, ".gen.go")
	isTest := strings.HasSuffix(pos.Filename, "_test.go")
	return fmt.Sprintf("%s:%d", rel, pos.Line), isGen, isTest
}

// strikeNamed returns t as a strike-defined *types.Named (unwrapping pointers
// and aliases), or nil.
func strikeNamed(t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok {
		return nil
	}
	obj := named.Obj()
	if obj.Pkg() == nil || !strings.HasPrefix(obj.Pkg().Path(), strikePrefix) {
		return nil
	}
	return named
}

// isScalarStrike reports whether t is a strike named type with basic underlying.
func isScalarStrike(t types.Type) bool {
	n := strikeNamed(t)
	if n == nil {
		return false
	}
	_, ok := n.Underlying().(*types.Basic)
	return ok
}

func isPlainString(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	if !ok {
		return false
	}
	// plain (or untyped) string that is NOT a named strike type
	return b.Info()&types.IsString != 0 && strikeNamed(t) == nil
}

func typeStr(t types.Type) string {
	if t == nil {
		return ""
	}
	return types.TypeString(t, func(p *types.Package) string {
		return strings.TrimPrefix(p.Path(), strikePrefix)
	})
}

func (c *collector) render(n ast.Node) string {
	var sb strings.Builder
	printer.Fprint(&sb, c.fset, n)
	s := sb.String()
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 220 {
		s = s[:220] + "..."
	}
	return s
}

// freeStrikeTyped reports whether expr references any identifier whose type is
// a strike named type (scalar or struct).
func freeStrikeTyped(info *types.Info, expr ast.Expr) (types.Type, bool) {
	var found types.Type
	ast.Inspect(expr, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || found != nil {
			return true
		}
		if obj := info.Uses[id]; obj != nil {
			if _, isVar := obj.(*types.Var); isVar && strikeNamed(obj.Type()) != nil {
				found = obj.Type()
				return false
			}
		}
		return true
	})
	return found, found != nil
}

// usesObj reports whether expr references the given object.
func usesObj(info *types.Info, expr ast.Expr, target types.Object) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && info.Uses[id] == target {
			found = true
			return false
		}
		return !found
	})
	return found
}

// asConversion returns (targetType, argExpr) if call is a type conversion.
func asConversion(info *types.Info, call *ast.CallExpr) (types.Type, ast.Expr, bool) {
	if len(call.Args) != 1 {
		return nil, nil, false
	}
	tv, ok := info.Types[call.Fun]
	if !ok || !tv.IsType() {
		return nil, nil, false
	}
	return tv.Type, call.Args[0], true
}

type funcCtx struct {
	name string
	sig  string
	decl *ast.FuncDecl
}

func (c *collector) walkFile(pkg *packages.Package, file *ast.File) {
	// Stack-based walk to know enclosing function and parent node.
	var stack []ast.Node
	var fn funcCtx
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		if fd, ok := n.(*ast.FuncDecl); ok {
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) > 0 {
				name = c.render(fd.Recv.List[0].Type) + "." + name
			}
			fn = funcCtx{name: name, sig: c.render(fd.Type), decl: fd}
			c.analyzeFuncDecl(pkg, fd, fn)
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			c.analyzeCall(pkg, node, stack, fn)
		case *ast.MapType:
			c.analyzeMapType(pkg, node, stack, fn)
		case *ast.IndexExpr:
			c.analyzeIndex(pkg, node, fn)
		}
		return true
	}
	ast.Inspect(file, visit)
}

// context of a conversion: what syntactic role the converted value plays.
func (c *collector) convContext(info *types.Info, stack []ast.Node, conv *ast.CallExpr) string {
	// stack[len-1] == conv; parent is stack[len-2]
	for i := len(stack) - 2; i >= 0; i-- {
		switch p := stack[i].(type) {
		case *ast.ParenExpr:
			continue
		case *ast.CallExpr:
			for _, a := range p.Args {
				if a == stack[i+1] {
					return "call-arg:" + c.calleeFQN(info, p)
				}
			}
			return "call-fun"
		case *ast.ReturnStmt:
			return "return"
		case *ast.AssignStmt:
			return "assign"
		case *ast.KeyValueExpr:
			return "composite-field:" + c.render(p.Key)
		case *ast.IndexExpr:
			if p.Index == stack[i+1] {
				return "map-index"
			}
			return "index-base"
		case *ast.BinaryExpr:
			return "binop:" + p.Op.String()
		case *ast.CaseClause:
			return "switch-case"
		case *ast.ValueSpec:
			return "var-decl"
		case *ast.CompositeLit:
			return "composite-elem"
		case *ast.RangeStmt:
			return "range"
		case *ast.SwitchStmt:
			return "switch-tag"
		default:
			return fmt.Sprintf("other:%T", p)
		}
	}
	return "toplevel"
}

func (c *collector) calleeFQN(info *types.Info, call *ast.CallExpr) string {
	switch f := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		if obj := info.Uses[f]; obj != nil && obj.Pkg() != nil {
			return strings.TrimPrefix(obj.Pkg().Path(), strikePrefix) + "." + f.Name
		}
		return f.Name
	case *ast.SelectorExpr:
		if obj := info.Uses[f.Sel]; obj != nil {
			if fnObj, ok := obj.(*types.Func); ok {
				return strings.TrimPrefix(fnObj.FullName(), strikePrefix)
			}
			if obj.Pkg() != nil {
				return strings.TrimPrefix(obj.Pkg().Path(), strikePrefix) + "." + f.Sel.Name
			}
		}
		return c.render(f)
	}
	return c.render(call.Fun)
}

func enclosingStmt(stack []ast.Node) ast.Node {
	for i := len(stack) - 1; i >= 0; i-- {
		if _, ok := stack[i].(ast.Stmt); ok {
			return stack[i]
		}
	}
	return stack[len(stack)-1]
}

func (c *collector) analyzeCall(pkg *packages.Package, call *ast.CallExpr, stack []ast.Node, fn funcCtx) {
	info := pkg.TypesInfo
	target, arg, ok := asConversion(info, call)
	if !ok {
		return
	}
	src := info.TypeOf(arg)
	tNamed, sNamed := strikeNamed(target), strikeNamed(src)
	if tNamed == nil && sNamed == nil {
		return
	}
	pos, isGen, isTest := c.relPos(call.Pos())
	ctx := c.convContext(info, stack, call)
	c.emit(Fact{
		Kind: "conversion", Pos: pos, Pkg: pkg.PkgPath, Func: fn.name,
		From: typeStr(src), To: typeStr(target), Context: ctx,
		Snippet: c.render(enclosingStmt(stack)), IsGen: isGen, IsTest: isTest,
	})

	// roundtrip-nested: the argument is itself a conversion
	if inner, ok := ast.Unparen(arg).(*ast.CallExpr); ok {
		if innerTarget, innerArg, ok2 := asConversion(info, inner); ok2 {
			innerSrc := info.TypeOf(innerArg)
			if strikeNamed(innerSrc) != nil || strikeNamed(innerTarget) != nil ||
				tNamed != nil || sNamed != nil {
				c.emit(Fact{
					Kind: "roundtrip-nested", Pos: pos, Pkg: pkg.PkgPath, Func: fn.name,
					From: typeStr(innerSrc), To: typeStr(target),
					Detail:  fmt.Sprintf("via %s", typeStr(innerTarget)),
					Snippet: c.render(call), IsGen: isGen, IsTest: isTest,
				})
			}
		}
	}

	// retype-from-stringop: conversion TO a strike scalar whose arg is a call
	if tNamed != nil && isScalarStrike(target) {
		if inner, ok := ast.Unparen(arg).(*ast.CallExpr); ok {
			if _, _, isConv := asConversion(info, inner); !isConv {
				c.emit(Fact{
					Kind: "retype-from-stringop", Pos: pos, Pkg: pkg.PkgPath, Func: fn.name,
					From: c.calleeFQN(info, inner), To: typeStr(target),
					Snippet: c.render(call), IsGen: isGen, IsTest: isTest,
				})
			}
		}
		if _, ok := ast.Unparen(arg).(*ast.BinaryExpr); ok {
			c.emit(Fact{
				Kind: "retype-from-stringop", Pos: pos, Pkg: pkg.PkgPath, Func: fn.name,
				From: "string-concat", To: typeStr(target),
				Snippet: c.render(call), IsGen: isGen, IsTest: isTest,
			})
		}
	}
}

func (c *collector) analyzeMapType(pkg *packages.Package, mt *ast.MapType, stack []ast.Node, fn funcCtx) {
	info := pkg.TypesInfo
	keyType := info.TypeOf(mt.Key)
	if !isPlainString(keyType) {
		return
	}
	pos, isGen, isTest := c.relPos(mt.Pos())
	ctx := "type-expr"
	for i := len(stack) - 2; i >= 0; i-- {
		switch p := stack[i].(type) {
		case *ast.Field:
			names := []string{}
			for _, nm := range p.Names {
				names = append(names, nm.Name)
			}
			ctx = "field:" + strings.Join(names, ",")
		case *ast.TypeSpec:
			ctx = "typedecl:" + p.Name.Name
		case *ast.StructType:
			continue
		case *ast.FieldList:
			continue
		case *ast.FuncType:
			ctx = "func-signature"
		case *ast.CompositeLit:
			ctx = "composite-lit"
		case *ast.CallExpr:
			ctx = "make-or-conv"
		case *ast.ValueSpec:
			ctx = "var-decl"
		default:
			_ = p
		}
		break
	}
	c.emit(Fact{
		Kind: "map-string-key", Pos: pos, Pkg: pkg.PkgPath, Func: fn.name,
		To: typeStr(info.TypeOf(mt)), Context: ctx,
		IsGen: isGen, IsTest: isTest,
	})
}

func (c *collector) analyzeIndex(pkg *packages.Package, ix *ast.IndexExpr, fn funcCtx) {
	info := pkg.TypesInfo
	baseType := info.TypeOf(ix.X)
	if baseType == nil {
		return
	}
	m, ok := types.Unalias(baseType).Underlying().(*types.Map)
	if !ok || !isPlainString(m.Key()) {
		return
	}
	if t, ok := freeStrikeTyped(info, ix.Index); ok {
		pos, isGen, isTest := c.relPos(ix.Pos())
		c.emit(Fact{
			Kind: "map-index-typed-source", Pos: pos, Pkg: pkg.PkgPath, Func: fn.name,
			From: typeStr(t), To: typeStr(baseType),
			Snippet: c.render(ix), IsGen: isGen, IsTest: isTest,
		})
	}
}

func (c *collector) analyzeFuncDecl(pkg *packages.Package, fd *ast.FuncDecl, fn funcCtx) {
	info := pkg.TypesInfo
	if fd.Type.Params == nil {
		return
	}
	pos, isGen, isTest := c.relPos(fd.Pos())

	type param struct {
		obj  types.Object
		name string
	}
	var stringParams, typedParams []param
	for _, field := range fd.Type.Params.List {
		t := info.TypeOf(field.Type)
		for _, nm := range field.Names {
			obj := info.Defs[nm]
			if obj == nil {
				continue
			}
			if isPlainString(t) || isPlainStringSliceOrMap(t) {
				stringParams = append(stringParams, param{obj, nm.Name})
				if scalarName.MatchString(nm.Name) {
					c.emit(Fact{
						Kind: "param-string-scalar-name", Pos: pos, Pkg: pkg.PkgPath,
						Func: fn.name, FuncSig: fn.sig,
						Detail: nm.Name + " " + typeStr(t),
						IsGen:  isGen, IsTest: isTest,
					})
				}
			}
			if isScalarStrike(t) || strikeNamed(t) != nil && !isScalarStrike(t) && isAddressLike(t) {
				typedParams = append(typedParams, param{obj, nm.Name})
			}
		}
	}
	if fd.Body == nil {
		return
	}

	// scan body for conversions touching params, and local roundtrips
	type localConv struct {
		obj  types.Object // variable holding the conversion result
		from types.Type
		to   types.Type
		pos  token.Pos
	}
	var locals []localConv

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, rhs := range node.Rhs {
				call, ok := ast.Unparen(rhs).(*ast.CallExpr)
				if !ok {
					continue
				}
				target, arg, ok := asConversion(info, call)
				if !ok {
					continue
				}
				src := info.TypeOf(arg)
				if strikeNamed(target) == nil && strikeNamed(src) == nil {
					continue
				}
				if id, ok := node.Lhs[i].(*ast.Ident); ok {
					if obj := info.Defs[id]; obj != nil {
						locals = append(locals, localConv{obj, src, target, call.Pos()})
					} else if obj := info.Uses[id]; obj != nil {
						locals = append(locals, localConv{obj, src, target, call.Pos()})
					}
				}
			}
		case *ast.CallExpr:
			target, arg, ok := asConversion(info, node)
			if !ok {
				return true
			}
			src := info.TypeOf(arg)
			// param-string-typed-in-body: plain-string param converted to strike type
			if strikeNamed(target) != nil {
				for _, p := range stringParams {
					if usesObj(info, arg, p.obj) {
						cpos, _, _ := c.relPos(node.Pos())
						c.emit(Fact{
							Kind: "param-string-typed-in-body", Pos: pos, Pkg: pkg.PkgPath,
							Func: fn.name, FuncSig: fn.sig,
							From: p.name + " string", To: typeStr(target),
							Detail:  "conversion at " + cpos,
							Snippet: c.render(node), IsGen: isGen, IsTest: isTest,
						})
					}
				}
			}
			// param-detyped-in-body: strike-typed param converted to basic
			if strikeNamed(src) != nil && strikeNamed(target) == nil {
				for _, p := range typedParams {
					if usesObj(info, arg, p.obj) {
						cpos, _, _ := c.relPos(node.Pos())
						c.emit(Fact{
							Kind: "param-detyped-in-body", Pos: pos, Pkg: pkg.PkgPath,
							Func: fn.name, FuncSig: fn.sig,
							From: p.name + " " + typeStr(src), To: typeStr(target),
							Detail:  "conversion at " + cpos,
							Snippet: c.render(node), IsGen: isGen, IsTest: isTest,
						})
					}
				}
			}
			// roundtrip-local: conversion whose arg uses a local holding a prior conversion
			for _, lc := range locals {
				if node.Pos() > lc.pos && usesObj(info, arg, lc.obj) {
					wasDetype := strikeNamed(lc.from) != nil && strikeNamed(lc.to) == nil
					isRetype := strikeNamed(target) != nil
					wasRetype := strikeNamed(lc.to) != nil
					isDetype := strikeNamed(target) == nil && strikeNamed(src) != nil
					if (wasDetype && isRetype) || (wasRetype && isDetype) {
						cpos, _, _ := c.relPos(node.Pos())
						c.emit(Fact{
							Kind: "roundtrip-local", Pos: cpos, Pkg: pkg.PkgPath,
							Func: fn.name,
							From: typeStr(lc.from), To: typeStr(target),
							Detail:  fmt.Sprintf("via local %q (%s)", lc.obj.Name(), typeStr(lc.to)),
							Snippet: c.render(node), IsGen: isGen, IsTest: isTest,
						})
					}
				}
			}
		case *ast.ReturnStmt:
			// result-string-scalar: returning string(strikeTyped) from a func
			for _, res := range node.Results {
				call, ok := ast.Unparen(res).(*ast.CallExpr)
				if !ok {
					continue
				}
				target, arg, ok := asConversion(info, call)
				if !ok {
					continue
				}
				if isPlainString(target) && strikeNamed(info.TypeOf(arg)) != nil {
					cpos, _, _ := c.relPos(call.Pos())
					c.emit(Fact{
						Kind: "result-string-scalar", Pos: cpos, Pkg: pkg.PkgPath,
						Func: fn.name, FuncSig: fn.sig,
						From: typeStr(info.TypeOf(arg)), To: "string",
						Snippet: c.render(node), IsGen: isGen, IsTest: isTest,
					})
				}
			}
		}
		return true
	})
}

func isPlainStringSliceOrMap(t types.Type) bool {
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Slice:
		return isPlainString(u.Elem())
	case *types.Map:
		return isPlainString(u.Key())
	}
	return false
}

func isAddressLike(t types.Type) bool {
	// strike named struct types participate in typed-param analysis too
	n := strikeNamed(t)
	if n == nil {
		return false
	}
	_, ok := n.Underlying().(*types.Struct)
	return ok
}
