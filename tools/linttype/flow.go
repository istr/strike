package main

import (
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"go/types"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const strikePrefix = "github.com/istr/strike/"

// skipPackage reports whether the extractor should record no facts for the
// package at path: outside the strike module; the synthetic test-binary main
// for a tested package (a generated testmain.go in the build cache, outside
// any module tree -- the package's real files are analyzed under the
// "pkg [pkg.test]" variant, which still matches the module-prefix check
// below); or the tools tree, hand-written Go with no CUE-generated
// vocabulary, so the named types resolved there are this tool's own
// scaffolding rather than the contract vocabulary the gates exist for --
// .go-arch-lint.yml excludes the same tree for the same reason. A measuring
// instrument does not measure itself. The analysis-pass gate and the
// go/packages survey both call this so the two traversals cannot drift apart.
func skipPackage(path string) bool {
	if !strings.HasPrefix(path, strikePrefix) && path != "github.com/istr/strike" {
		return true
	}
	if strings.HasSuffix(path, ".test") {
		return true
	}
	return strings.HasPrefix(path, strikePrefix+"tools/")
}

// Fact is one observation of the extractor. The survey records every kind
// below; the gates cover conv-owner, roundtrip-local, result-string-scalar and
// detype-bypasses-stringer, the near-zero-false-positive classes:
//
//   - conversion: every type conversion involving a strike-defined named type,
//     with syntactic context (call-arg, return, assign, map-index, binop, ...)
//   - conv-owner: a conversion sitting directly in a call argument, outside
//     the defining package of the type being converted
//   - roundtrip-nested: T(string(x)) / string(T(s)) directly nested
//   - roundtrip-local: v := string(x) or v := x.String() ... T(v) (and inverse)
//     within one function
//   - param-string-typed-in-body: func has a plain-string(ish) param that the
//     body converts to a strike named type (typing starts too late)
//   - param-detyped-in-body: func has a strike-typed param that the body takes
//     back to a basic type, by conversion or through the String() boundary
//     (typing breaks too early)
//   - param-string-scalar-name: plain-string param whose name suggests a
//     scalar semantic (host, digest, id, ...) -- raw candidates, unfiltered
//   - result-string-scalar: func result is plain string but a return statement
//     returns a detyped strike value
//   - detype-bypasses-stringer: string(x) where the type of x owns a String()
//     boundary method, outside that type's own methods -- the call site should
//     read x.String()
//   - map-string-key: every map type literal with a plain string key
//   - map-index-typed-source: index into a string-keyed map where the key
//     expression is built from strike-typed values
//   - retype-from-stringop: conversion to a strike named type whose argument
//     is a function call (Sprintf, TrimSuffix, ...) -- grammar rebuilt outside
//     the owning type
//
// A String() string method that detypes its own receiver is the sanctioned
// boundary where a named scalar becomes a plain string; ADR-049 (3) carves out
// that one method name and no other. The survey still records it as a
// result-string-scalar fact, flagged isboundary, and the gate drops it the way
// it drops generated code. Every other detyping of a type that owns such a
// boundary is a bypass and gates.
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
	// IsBoundary marks a sanctioned stringification method detyping its own
	// receiver. The survey keeps the fact; the gate drops it.
	IsBoundary bool `json:"isboundary,omitempty"`
	// tokenPos is where an analyzer reports the finding. It is unexported, so
	// the JSONL survey is unaffected by it.
	tokenPos token.Pos
}

var scalarName = regexp.MustCompile(`(?i)(host|port|digest|path|id$|ids$|name$|ref|refs$|authority|image|commit|sha|hash|url|uri|addr|fingerprint|issuer|subject|user|tag|duration|timestamp|secret)`)

// unit is the per-package input the walk needs. Its field names match the
// go/packages fields they stand in for, so the same methods serve a
// packages.Load result and an analysis pass without a second walk.
type unit struct {
	TypesInfo *types.Info
	PkgPath   string
}

type collector struct {
	seen     map[string]bool
	fset     *token.FileSet
	repoRoot string
	facts    []Fact
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

// allow tolerates one covered class in one function until its owning roadmap
// item retypes it. It serves every gate in this tool: an entry is matched on
// (pkg, func, kind), so the conversion-ownership gate and the flow gates share
// one shape instead of two. The single entry below is a test-side round trip
// whose correct repair is a constructor signature change, not a call-site
// edit.
var allow = []allowEntry{
	{
		pkg:    "github.com/istr/strike/internal/primitive_test",
		fn:     "TestDigestHexFromHexRoundTrip",
		kind:   "roundtrip-local",
		owner:  "item-0082",
		reason: "the hex constructor's own inverse test; retyping DigestFromHex to take Sha256 reaches roughly a hundred call sites",
	},
}

// gatingKinds are the near-zero-false-positive classes the gate enforces. The
// survey still records every kind; only these fail the build.
var gatingKinds = map[string]bool{
	"conv-owner":               true,
	"roundtrip-local":          true,
	"result-string-scalar":     true,
	"detype-bypasses-stringer": true,
}

// convKinds and flowKinds split the gating set between the two analyzers that
// report it. gateFindings still applies the common drops.
var convKinds = map[string]bool{"conv-owner": true}

var flowKinds = map[string]bool{
	"roundtrip-local":          true,
	"result-string-scalar":     true,
	"detype-bypasses-stringer": true,
}

// boundaryMethod is the single method name allowed to hand a named scalar out
// as a plain string. ADR-049 (3) carves out exactly one name -- fmt.Stringer
// is a foreign interface and the value it produces is a message, not program
// state -- so this is a constant rather than a set. The method must also be
// declared as () string on the type it renders; see isBoundarySig.
const boundaryMethod = "String"

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
// fixable), drops sanctioned stringification boundaries, and drops allowlisted
// sites.
func gateFindings(facts []Fact, allow []allowEntry) []Fact {
	var out []Fact
	for _, f := range facts {
		if !gatingKinds[f.Kind] || f.IsGen || f.IsBoundary {
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
	switch f.Kind {
	case "conv-owner":
		return f.Detail
	case "result-string-scalar":
		return fmt.Sprintf("%s: %s returned as plain string in %s; return the named type or convert at the call boundary",
			f.Kind, f.From, f.Func)
	case "detype-bypasses-stringer":
		return fmt.Sprintf("%s: %s owns a String() boundary but %s detypes it with %s; call the String() method instead",
			f.Kind, f.From, f.Func, f.Detail)
	}
	return fmt.Sprintf("%s: %s detyped to %s and retyped in %s (%s); keep the value typed end to end",
		f.Kind, f.From, f.To, f.Func, f.Detail)
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
		if skipPackage(pkg.PkgPath) {
			continue
		}
		c.fset = pkg.Fset
		u := unit{PkgPath: pkg.PkgPath, TypesInfo: pkg.TypesInfo}
		for _, file := range pkg.Syntax {
			fname := c.fset.Position(file.Pos()).Filename
			if !strings.HasPrefix(fname, c.repoRoot) {
				continue // cgo/generated outside tree
			}
			c.walkFile(u, file)
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

// at stamps the reporting position on a fact. Every emitted fact goes through
// it, so a gate always has somewhere to point.
func (f Fact) at(p token.Pos) Fact {
	f.tokenPos = p
	return f
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

// isBoundarySig reports whether sig has the nullary string-returning shape
// fmt.Stringer requires.
func isBoundarySig(sig *types.Signature) bool {
	if sig == nil || sig.Variadic() || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return false
	}
	return isPlainString(sig.Results().At(0).Type())
}

// hasStringBoundary reports whether t is a strike named type owning a
// String() string method: the sanctioned way to render it as a plain string,
// and therefore the reason a bare string(x) elsewhere is a bypass.
func hasStringBoundary(t types.Type) bool {
	n := strikeNamed(t)
	if n == nil {
		return false
	}
	obj, _, _ := types.LookupFieldOrMethod(n, true, n.Obj().Pkg(), boundaryMethod)
	fn, ok := obj.(*types.Func)
	if !ok {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	return ok && isBoundarySig(sig)
}

// sameNamed reports whether a and b are the same strike named type, which is
// how a method is recognized as belonging to the type it detypes.
func sameNamed(a, b types.Type) bool {
	na, nb := strikeNamed(a), strikeNamed(b)
	return na != nil && nb != nil && na.Obj() == nb.Obj()
}

// bypassesStringer reports whether a conversion from src to target hands out
// a value whose type owns a String() boundary, from outside that type's own
// methods. recv is the receiver type of the enclosing method, nil for a plain
// func: a type owns its representation, so converting inside its own methods
// is not a bypass, but every other site must go through the boundary.
func bypassesStringer(target, src, recv types.Type) bool {
	return isPlainString(target) && hasStringBoundary(src) && !sameNamed(recv, src)
}

// boundaryRecv returns the receiver object of fd when fd is the sanctioned
// stringification method on a strike named type: String declared as () string.
// It returns nil for everything else, including a package-level func of the
// same name and a method with an unnamed receiver, so those keep gating.
func boundaryRecv(info *types.Info, fd *ast.FuncDecl) types.Object {
	if fd.Recv == nil || len(fd.Recv.List) != 1 || fd.Name.Name != boundaryMethod {
		return nil
	}
	names := fd.Recv.List[0].Names
	if len(names) != 1 {
		return nil
	}
	recv := info.Defs[names[0]]
	if recv == nil || strikeNamed(recv.Type()) == nil {
		return nil
	}
	fn, ok := info.Defs[fd.Name].(*types.Func)
	if !ok {
		return nil
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || !isBoundarySig(sig) {
		return nil
	}
	return recv
}

// isRecvIdent reports whether expr is exactly the receiver identifier. A
// boundary method may only detype itself: string(d) is sanctioned, but
// string(c.cfg.Host) is a leak wearing a Stringer's clothes.
func isRecvIdent(info *types.Info, expr ast.Expr, recv types.Object) bool {
	if recv == nil {
		return false
	}
	id, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && info.Uses[id] == recv
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
	if err := printer.Fprint(&sb, c.fset, n); err != nil {
		return fmt.Sprintf("<unprintable node: %v>", err)
	}
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

// asBoundaryCall returns (string, x) if call is x.String() on a type that owns
// the boundary method. Such a call takes the value out of its named type
// exactly as string(x) does.
func asBoundaryCall(info *types.Info, call *ast.CallExpr) (types.Type, ast.Expr, bool) {
	if len(call.Args) != 0 {
		return nil, nil, false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != boundaryMethod {
		return nil, nil, false
	}
	if !hasStringBoundary(info.TypeOf(sel.X)) {
		return nil, nil, false
	}
	return types.Typ[types.String], sel.X, true
}

// asDetyping returns the target type and source expression of a step that
// moves a value across the named-type boundary in either direction: a type
// conversion, or the String() boundary call. Detecting a roundtrip through
// conversions alone would go blind the moment a detyping is rewritten to the
// sanctioned boundary call, which leaves the value just as untyped.
func asDetyping(info *types.Info, call *ast.CallExpr) (types.Type, ast.Expr, bool) {
	if target, arg, ok := asConversion(info, call); ok {
		return target, arg, true
	}
	return asBoundaryCall(info, call)
}

// localConv is a local variable holding the result of a detyping or retyping
// step: the type the value had before the step, the type it took, and where
// the step sits, so a later step in the same body can be paired against it.
type localConv struct {
	obj  types.Object
	from types.Type
	to   types.Type
	pos  token.Pos
}

type funcCtx struct {
	decl *ast.FuncDecl
	// recv is the receiver type of the enclosing method, nil for a plain
	// func. A type owns its own representation, so a conversion inside one of
	// its methods is not a boundary bypass.
	recv types.Type
	name string
	sig  string
}

func (c *collector) walkFile(pkg unit, file *ast.File) {
	// Stack-based walk to know enclosing function and parent node.
	var stack []ast.Node
	var fn funcCtx
	visit := func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		if fd, ok := n.(*ast.FuncDecl); ok {
			name := fd.Name.Name
			var recv types.Type
			if fd.Recv != nil && len(fd.Recv.List) > 0 {
				name = c.render(fd.Recv.List[0].Type) + "." + name
				recv = pkg.TypesInfo.TypeOf(fd.Recv.List[0].Type)
			}
			fn = funcCtx{name: name, sig: c.render(fd.Type), decl: fd, recv: recv}
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
// stack's last element is the conversion call itself; this walks its ancestors.
func (c *collector) convContext(info *types.Info, stack []ast.Node) string {
	for i := len(stack) - 2; i >= 0; i-- {
		switch p := stack[i].(type) {
		case *ast.ParenExpr:
			continue
		case *ast.CallExpr:
			return c.callContext(info, p, stack[i+1])
		case *ast.ReturnStmt:
			return "return"
		case *ast.AssignStmt:
			return "assign"
		case *ast.KeyValueExpr:
			return "composite-field:" + c.render(p.Key)
		case *ast.IndexExpr:
			return indexContext(p, stack[i+1])
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

// callContext names the role child plays in call p: an argument carries the
// callee's name, anything else is the callee position itself.
func (c *collector) callContext(info *types.Info, p *ast.CallExpr, child ast.Node) string {
	for _, a := range p.Args {
		if a == child {
			return "call-arg:" + c.calleeFQN(info, p)
		}
	}
	return "call-fun"
}

// indexContext names the role child plays in index expression p: the key of a
// lookup, or the collection being looked into.
func indexContext(p *ast.IndexExpr, child ast.Node) string {
	if p.Index == child {
		return "map-index"
	}
	return "index-base"
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

// convSite is one type conversion plus the provenance every fact emitted for
// it shares, so the per-kind analyzers below take one value instead of the
// same six arguments each.
type convSite struct {
	call   *ast.CallExpr
	arg    ast.Expr
	target types.Type
	src    types.Type
	pos    string
	isGen  bool
	isTest bool
}

func (c *collector) analyzeCall(pkg unit, call *ast.CallExpr, stack []ast.Node, fn funcCtx) {
	info := pkg.TypesInfo
	target, arg, ok := asConversion(info, call)
	if !ok {
		return
	}
	src := info.TypeOf(arg)
	if strikeNamed(target) == nil && strikeNamed(src) == nil {
		return
	}
	pos, isGen, isTest := c.relPos(call.Pos())
	ctx := c.convContext(info, stack)
	c.emit(Fact{
		Kind: "conversion", Pos: pos, Pkg: pkg.PkgPath, Func: fn.name,
		From: typeStr(src), To: typeStr(target), Context: ctx,
		Snippet: c.render(enclosingStmt(stack)), IsGen: isGen, IsTest: isTest,
	})

	// detype-bypasses-stringer: a plain-string conversion of a value whose type
	// owns a String() boundary, made outside that type's own methods.
	if bypassesStringer(target, src, fn.recv) {
		c.emit(Fact{
			Kind: "detype-bypasses-stringer", Pos: pos, Pkg: pkg.PkgPath, Func: fn.name,
			From: typeStr(src), To: typeStr(target), Context: ctx,
			Detail:  c.render(call),
			Snippet: c.render(enclosingStmt(stack)), IsGen: isGen, IsTest: isTest,
		}.at(call.Pos()))
	}

	// conv-owner: the conversion sits directly in a call argument and neither
	// the target nor the source type is defined here, so the boundary is being
	// written outside the package that owns the type's behavior. This is the
	// same finding the separate ownership analyzer made, taken from the
	// traversal that already resolved the types.
	if strings.HasPrefix(ctx, "call-arg:") {
		named := strikeNamed(target)
		if named == nil {
			named = strikeNamed(src)
		}
		if named != nil && !ownsConversion(pkg.PkgPath, strikeNamed(target), strikeNamed(src)) {
			c.emit(Fact{
				Kind: "conv-owner", Pos: pos, Pkg: pkg.PkgPath, Func: fn.name,
				From: typeStr(src), To: typeStr(target), Context: ctx,
				Detail: fmt.Sprintf(
					"conversion of %s in a call argument; type the source or own the conversion in %s",
					named.Obj().Name(), named.Obj().Pkg().Path()),
				Snippet: c.render(enclosingStmt(stack)), IsGen: isGen, IsTest: isTest,
			}.at(call.Pos()))
		}
	}

	cv := convSite{call: call, arg: arg, target: target, src: src, pos: pos, isGen: isGen, isTest: isTest}
	c.analyzeRoundtripNested(pkg, cv, fn)
	c.analyzeRetypeFromStringop(pkg, cv, fn)
}

// analyzeRoundtripNested records T(string(x)) / string(T(s)) written as one
// directly nested pair of conversions.
func (c *collector) analyzeRoundtripNested(pkg unit, cv convSite, fn funcCtx) {
	info := pkg.TypesInfo
	inner, ok := ast.Unparen(cv.arg).(*ast.CallExpr)
	if !ok {
		return
	}
	innerTarget, innerArg, ok := asConversion(info, inner)
	if !ok {
		return
	}
	innerSrc := info.TypeOf(innerArg)
	if strikeNamed(innerSrc) == nil && strikeNamed(innerTarget) == nil &&
		strikeNamed(cv.target) == nil && strikeNamed(cv.src) == nil {
		return
	}
	c.emit(Fact{
		Kind: "roundtrip-nested", Pos: cv.pos, Pkg: pkg.PkgPath, Func: fn.name,
		From: typeStr(innerSrc), To: typeStr(cv.target),
		Detail:  fmt.Sprintf("via %s", typeStr(innerTarget)),
		Snippet: c.render(cv.call), IsGen: cv.isGen, IsTest: cv.isTest,
	})
}

// analyzeRetypeFromStringop records a conversion to a strike scalar whose
// argument is a string built somewhere else -- a call result or a
// concatenation -- which rebuilds the type's grammar outside the owning type.
func (c *collector) analyzeRetypeFromStringop(pkg unit, cv convSite, fn funcCtx) {
	info := pkg.TypesInfo
	if !isScalarStrike(cv.target) {
		return
	}
	if inner, ok := ast.Unparen(cv.arg).(*ast.CallExpr); ok {
		if _, _, isConv := asConversion(info, inner); !isConv {
			c.emit(Fact{
				Kind: "retype-from-stringop", Pos: cv.pos, Pkg: pkg.PkgPath, Func: fn.name,
				From: c.calleeFQN(info, inner), To: typeStr(cv.target),
				Snippet: c.render(cv.call), IsGen: cv.isGen, IsTest: cv.isTest,
			})
		}
	}
	if _, ok := ast.Unparen(cv.arg).(*ast.BinaryExpr); ok {
		c.emit(Fact{
			Kind: "retype-from-stringop", Pos: cv.pos, Pkg: pkg.PkgPath, Func: fn.name,
			From: "string-concat", To: typeStr(cv.target),
			Snippet: c.render(cv.call), IsGen: cv.isGen, IsTest: cv.isTest,
		})
	}
}

func (c *collector) analyzeMapType(pkg unit, mt *ast.MapType, stack []ast.Node, fn funcCtx) {
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

func (c *collector) analyzeIndex(pkg unit, ix *ast.IndexExpr, fn funcCtx) {
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

// param is one named parameter of a declaration, kept together with the object
// its uses in the body resolve to, so a conversion can be traced back to it.
type param struct {
	obj  types.Object
	name string
}

// params splits a declaration's parameters into the two sets the body checks
// need: the plain-string ones typing may start too late for, and the
// strike-typed ones typing may break too early on.
type params struct {
	str   []param
	typed []param
}

// site is where a declaration's facts are filed and which gate drops apply to
// them. It travels with the checks so each one does not recompute it.
type site struct {
	pos    string
	isGen  bool
	isTest bool
}

func (c *collector) analyzeFuncDecl(pkg unit, fd *ast.FuncDecl, fn funcCtx) {
	if fd.Type.Params == nil {
		return
	}
	pos, isGen, isTest := c.relPos(fd.Pos())
	s := site{pos: pos, isGen: isGen, isTest: isTest}
	ps := c.declParams(pkg, fd, fn, s)
	if fd.Body == nil {
		return
	}
	boundary := boundaryRecv(pkg.TypesInfo, fd)

	// Locals accumulate as the walk goes, so a later step in the same body can
	// be paired against an earlier one.
	var locals []localConv

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			collectLocals(pkg.TypesInfo, node, &locals)
		case *ast.CallExpr:
			c.analyzeParamFlow(pkg, node, fn, ps, s, locals)
		case *ast.ReturnStmt:
			c.analyzeResultString(pkg, node, fn, boundary, s)
		}
		return true
	})
}

// declParams classifies every named parameter of the declaration.
func (c *collector) declParams(pkg unit, fd *ast.FuncDecl, fn funcCtx, s site) params {
	var ps params
	for _, field := range fd.Type.Params.List {
		t := pkg.TypesInfo.TypeOf(field.Type)
		for _, nm := range field.Names {
			p, isStr, isTyped := c.classifyParam(pkg, fn, s, t, nm)
			if isStr {
				ps.str = append(ps.str, p)
			}
			if isTyped {
				ps.typed = append(ps.typed, p)
			}
		}
	}
	return ps
}

// classifyParam reports which parameter sets nm belongs to, and records a
// plain-string parameter whose name suggests a scalar semantic.
func (c *collector) classifyParam(pkg unit, fn funcCtx, s site, t types.Type, nm *ast.Ident) (p param, isStr, isTyped bool) {
	obj := pkg.TypesInfo.Defs[nm]
	if obj == nil {
		return param{}, false, false
	}
	p = param{obj, nm.Name}
	if isPlainString(t) || isPlainStringSliceOrMap(t) {
		isStr = true
		if scalarName.MatchString(nm.Name) {
			c.emit(Fact{
				Kind: "param-string-scalar-name", Pos: s.pos, Pkg: pkg.PkgPath,
				Func: fn.name, FuncSig: fn.sig,
				Detail: nm.Name + " " + typeStr(t),
				IsGen:  s.isGen, IsTest: s.isTest,
			})
		}
	}
	if isScalarStrike(t) || strikeNamed(t) != nil && !isScalarStrike(t) && isAddressLike(t) {
		isTyped = true
	}
	return p, isStr, isTyped
}

// collectLocals records a local that took a value across the named-type
// boundary in either direction, so a later step can be paired against it.
func collectLocals(info *types.Info, stmt *ast.AssignStmt, locals *[]localConv) {
	if len(stmt.Lhs) != len(stmt.Rhs) {
		return
	}
	for i, rhs := range stmt.Rhs {
		call, ok := ast.Unparen(rhs).(*ast.CallExpr)
		if !ok {
			continue
		}
		target, arg, ok := asDetyping(info, call)
		if !ok {
			continue
		}
		src := info.TypeOf(arg)
		if strikeNamed(target) == nil && strikeNamed(src) == nil {
			continue
		}
		id, ok := stmt.Lhs[i].(*ast.Ident)
		if !ok {
			continue
		}
		obj := info.Defs[id]
		if obj == nil {
			obj = info.Uses[id]
		}
		if obj != nil {
			*locals = append(*locals, localConv{obj, src, target, call.Pos()})
		}
	}
}

// analyzeParamFlow records typing that starts too late on a plain-string
// parameter or breaks too early on a typed one, then hands the same call to
// the local-roundtrip check.
func (c *collector) analyzeParamFlow(pkg unit, node *ast.CallExpr, fn funcCtx, ps params, s site, locals []localConv) {
	info := pkg.TypesInfo
	target, arg, ok := asDetyping(info, node)
	if !ok {
		return
	}
	src := info.TypeOf(arg)
	// param-string-typed-in-body: plain-string param converted to strike type
	if strikeNamed(target) != nil {
		for _, p := range ps.str {
			if !usesObj(info, arg, p.obj) {
				continue
			}
			cpos, _, _ := c.relPos(node.Pos())
			c.emit(Fact{
				Kind: "param-string-typed-in-body", Pos: s.pos, Pkg: pkg.PkgPath,
				Func: fn.name, FuncSig: fn.sig,
				From: p.name + " string", To: typeStr(target),
				Detail:  "conversion at " + cpos,
				Snippet: c.render(node), IsGen: s.isGen, IsTest: s.isTest,
			})
		}
	}
	// param-detyped-in-body: strike-typed param taken back to a basic type, by
	// conversion or through the String() boundary
	if strikeNamed(src) != nil && strikeNamed(target) == nil {
		for _, p := range ps.typed {
			if !usesObj(info, arg, p.obj) {
				continue
			}
			cpos, _, _ := c.relPos(node.Pos())
			c.emit(Fact{
				Kind: "param-detyped-in-body", Pos: s.pos, Pkg: pkg.PkgPath,
				Func: fn.name, FuncSig: fn.sig,
				From: p.name + " " + typeStr(src), To: typeStr(target),
				Detail:  "detyped at " + cpos,
				Snippet: c.render(node), IsGen: s.isGen, IsTest: s.isTest,
			})
		}
	}
	c.analyzeRoundtripLocal(pkg, node, arg, target, fn, locals)
}

// analyzeResultString records a return statement that hands a strike named
// value out as a plain string.
func (c *collector) analyzeResultString(pkg unit, node *ast.ReturnStmt, fn funcCtx, boundary types.Object, s site) {
	info := pkg.TypesInfo
	for _, res := range node.Results {
		call, ok := ast.Unparen(res).(*ast.CallExpr)
		if !ok {
			continue
		}
		target, arg, ok := asConversion(info, call)
		if !ok {
			continue
		}
		if !isPlainString(target) || strikeNamed(info.TypeOf(arg)) == nil {
			continue
		}
		cpos, _, _ := c.relPos(call.Pos())
		c.emit(Fact{
			Kind: "result-string-scalar", Pos: cpos, Pkg: pkg.PkgPath,
			Func: fn.name, FuncSig: fn.sig,
			From: typeStr(info.TypeOf(arg)), To: "string",
			Snippet: c.render(node), IsGen: s.isGen, IsTest: s.isTest,
			IsBoundary: isRecvIdent(info, arg, boundary),
		}.at(call.Pos()))
	}
}

// analyzeRoundtripLocal records a step whose argument is a local holding an
// earlier step in the opposite direction: the value left its named type and
// came back, or came back and left again, both halves inside one body.
func (c *collector) analyzeRoundtripLocal(pkg unit, node *ast.CallExpr,
	arg ast.Expr, target types.Type, fn funcCtx, locals []localConv,
) {
	info := pkg.TypesInfo
	src := info.TypeOf(arg)
	for _, lc := range locals {
		if node.Pos() <= lc.pos || !usesObj(info, arg, lc.obj) {
			continue
		}
		wasDetype := strikeNamed(lc.from) != nil && strikeNamed(lc.to) == nil
		isRetype := strikeNamed(target) != nil
		wasRetype := strikeNamed(lc.to) != nil
		isDetype := strikeNamed(target) == nil && strikeNamed(src) != nil
		if (wasDetype && isRetype) || (wasRetype && isDetype) {
			cpos, isGen, isTest := c.relPos(node.Pos())
			c.emit(Fact{
				Kind: "roundtrip-local", Pos: cpos, Pkg: pkg.PkgPath,
				Func: fn.name,
				From: typeStr(lc.from), To: typeStr(target),
				Detail:  fmt.Sprintf("via local %q (%s)", lc.obj.Name(), typeStr(lc.to)),
				Snippet: c.render(node), IsGen: isGen, IsTest: isTest,
			}.at(node.Pos()))
		}
	}
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
