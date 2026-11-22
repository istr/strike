package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/build"
	"cuelang.org/go/cue/format"
	"cuelang.org/go/cue/load"
	"cuelang.org/go/cue/token"
)

// contractPrefix is the import path every contract package starts with.
const contractPrefix = modulePrefix + "contract/"

// contractTiers declares the tier of every package under contract/, numbered
// from the inside out as tierNames names them (ADR-048). A contract package
// imports only from a strictly lower tier.
var contractTiers = map[string]int{
	"primitive":   0,
	"endpoint":    1,
	"output":      1,
	"provenance":  1,
	"record":      1,
	"lane":        2,
	"attest":      2,
	"trustlayers": 2,
	"crossval":    3,
}

var tierNames = []string{"primitive", "concept", "wire", "vector"}

// contractFindings runs the contract lints over root/contract: the lints that
// read the CUE source and, unless a definition reaches itself, the lints that
// read the evaluated value, with the deferrals and exemptions of the
// empty-value check. While a definition reaches itself the evaluation does not
// run, so its walk always ends.
func contractFindings(root string, deferrals map[string][]string, exemptions []string) ([]string, error) {
	insts, err := contractInstances(root)
	if err != nil {
		return nil, err
	}
	findings, recursive := syntaxFindings(insts)
	if !recursive {
		var vfs []string
		vfs, err = valueFindings(insts, deferrals, exemptions)
		if err != nil {
			return nil, err
		}
		findings = append(findings, vfs...)
	}
	sort.Strings(findings)
	return slices.Compact(findings), nil
}

// contractInstances loads every package directory under root/contract and
// returns its build instance keyed by directory name. A directory that does not
// load as exactly one package aborts the run: a lint that skips what it cannot
// read reports a tree it has not seen as clean.
func contractInstances(root string) (map[string]*build.Instance, error) {
	entries, err := os.ReadDir(filepath.Join(root, "contract"))
	if err != nil {
		return nil, fmt.Errorf("read contract dir: %w", err)
	}
	insts := map[string]*build.Instance{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		loaded := load.Instances(
			[]string{"./contract/" + e.Name()}, &load.Config{Dir: root})
		if len(loaded) != 1 {
			return nil, fmt.Errorf("load contract/%s: %d instances, want 1", e.Name(), len(loaded))
		}
		if loaded[0].Err != nil {
			return nil, fmt.Errorf("load contract/%s: %w", e.Name(), loaded[0].Err)
		}
		insts[e.Name()] = loaded[0]
	}
	return insts, nil
}

// syntaxFindings runs the lints that read the CUE source of every contract
// package: inline string disjunctions (ADR-049 rule 5), re-inlined primitive
// grammars, lossy @go map-key redirects, imports that break the tier order, a
// default arm outside a regular field (ADR-049 rule 7), and definitions that
// reach themselves. These are properties of how the schema is written, so they
// read the syntax rather than the evaluated value. It also reports whether any
// definition reaches itself.
func syntaxFindings(insts map[string]*build.Instance) ([]string, bool) {
	var prims map[string]string
	if p, ok := insts["primitive"]; ok {
		prims = primitiveConstraints(p.Files)
	}
	var findings []string
	recursive := false
	for dir, inst := range insts {
		findings = appendTierFindings(findings, dir, inst.Files)
		for _, f := range inst.Files {
			ast.Walk(f, func(n ast.Node) bool {
				if field, ok := n.(*ast.Field); ok {
					findings = appendFieldFindings(findings, field, prims)
				}
				return true
			}, nil)
		}
		cycles := recursionFindings(inst.Files)
		recursive = recursive || len(cycles) > 0
		findings = append(findings, cycles...)
	}
	return findings, recursive
}

// primitiveConstraints maps the normalized source of each primitive definition
// constraint to its name, so a re-inlined grammar can be matched back to the
// primitive that already owns it. A definition whose value is a bare
// identifier -- string, or another definition -- owns no grammar and is left
// out; keyed by that identifier, it would claim every field of that type.
func primitiveConstraints(files []*ast.File) map[string]string {
	out := map[string]string{}
	for _, f := range files {
		for _, d := range f.Decls {
			field, ok := d.(*ast.Field)
			if !ok {
				continue
			}
			if _, bare := field.Value.(*ast.Ident); bare {
				continue
			}
			name := labelName(field.Label)
			if !isDefinitionLabel(name) {
				continue
			}
			if c := renderConstraint(field.Value); c != "" {
				out[c] = name
			}
		}
	}
	return out
}

// appendTierFindings reports a package directory with no declared tier, and
// every import of a declared package that does not name a contract package of
// a strictly lower tier.
func appendTierFindings(fs []string, dir string, files []*ast.File) []string {
	tier, ok := contractTiers[dir]
	if !ok {
		return append(fs, fmt.Sprintf(
			"contract/%s: undeclared-tier: package directory %q has no declared tier", dir, dir))
	}
	for _, f := range files {
		for spec := range f.ImportSpecs() {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				path = spec.Path.Value
			}
			// The one import from outside the contract: the standard package
			// struct, for the field forms of ADR-049 that need
			// struct.MinFields.
			if path == "struct" {
				continue
			}
			name, isContract := strings.CutPrefix(path, contractPrefix)
			to, declared := contractTiers[name]
			switch {
			case !isContract || !declared:
				fs = append(fs, finding(spec.Pos(), "undeclared-tier", fmt.Sprintf(
					"package %s imports %q, which is not a contract package with a declared tier",
					dir, path)))
			case to >= tier:
				fs = append(fs, finding(spec.Pos(), "tier-direction", fmt.Sprintf(
					"package %s (%s tier) imports %s (%s tier); a contract package imports only from a strictly lower tier",
					dir, tierNames[tier], name, tierNames[to])))
			}
		}
	}
	return fs
}

// recursionFindings reports every definition of one package that reaches
// itself through the definitions its value names, by a reference, a
// composition or an embedding (ADR-049). An identifier qualified by an import
// names a package of a lower tier, which cannot name this one back, so only an
// unqualified identifier can close a cycle.
func recursionFindings(files []*ast.File) []string {
	decls := map[string]*ast.Field{}
	for _, f := range files {
		for _, d := range f.Decls {
			if field, ok := d.(*ast.Field); ok && isDefinitionLabel(labelName(field.Label)) {
				decls[labelName(field.Label)] = field
			}
		}
	}
	refs := make(map[string][]string, len(decls))
	for name, field := range decls {
		refs[name] = localDefinitionRefs(field.Value, decls)
	}
	var fs []string
	for name, field := range decls {
		if chain := cycleFrom(name, refs); chain != nil {
			fs = append(fs, finding(field.Pos(), "recursive-definition", fmt.Sprintf(
				"definition %s reaches itself: %s", name, strings.Join(chain, " -> "))))
		}
	}
	return fs
}

// localDefinitionRefs returns, sorted and without repeats, every definition of
// decls that an unqualified identifier in e names. The label of a field and the
// selector of a qualified identifier are not references.
func localDefinitionRefs(e ast.Expr, decls map[string]*ast.Field) []string {
	seen := map[string]bool{}
	var visit func(ast.Node) bool
	visit = func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.Field:
			if _, ident := v.Label.(*ast.Ident); !ident {
				ast.Walk(v.Label, visit, nil)
			}
			if v.Value != nil {
				ast.Walk(v.Value, visit, nil)
			}
			return false
		case *ast.SelectorExpr:
			ast.Walk(v.X, visit, nil)
			return false
		case *ast.Ident:
			if _, ok := decls[v.Name]; ok {
				seen[v.Name] = true
			}
		}
		return true
	}
	ast.Walk(e, visit, nil)
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// cycleFrom returns a chain of definitions along refs from start back to
// start, or nil when start does not reach itself.
func cycleFrom(start string, refs map[string][]string) []string {
	seen := map[string]bool{start: true}
	path := []string{start}
	var reach func(string) bool
	reach = func(name string) bool {
		for _, next := range refs[name] {
			if next == start {
				path = append(path, next)
				return true
			}
			if seen[next] {
				continue
			}
			seen[next] = true
			path = append(path, next)
			if reach(next) {
				return true
			}
			path = path[:len(path)-1]
		}
		return false
	}
	if reach(start) {
		return path
	}
	return nil
}

func appendFieldFindings(fs []string, field *ast.Field, prims map[string]string) []string {
	name := labelName(field.Label)
	// ADR-049 rule 5: a string disjunction is a named type, never inline.
	if !isDefinitionLabel(name) && isStringDisjunction(field.Value) {
		fs = append(fs, finding(field.Pos(), "inline-string-disjunction", fmt.Sprintf(
			"field %q inlines a string disjunction; define a named type and reference it",
			name)))
	}
	if !isDefinitionLabel(name) {
		if prim, ok := prims[renderConstraint(field.Value)]; ok && prim != name {
			fs = append(fs, finding(field.Pos(), "primitive-reuse", fmt.Sprintf(
				"field %q re-inlines the grammar of primitive %s; reference %s instead",
				name, prim, prim)))
		}
	}
	if msg, ok := lossyMapKey(field); ok {
		fs = append(fs, finding(field.Pos(), "lossy-map-key", msg))
	}
	// ADR-049 rule 7: a default arm stands at a regular field, never at an
	// optional field and never in a definition of its own.
	if hasDefaultArm(field.Value) {
		switch {
		case field.Constraint == token.OPTION:
			fs = append(fs, finding(field.Pos(), "optional-default", fmt.Sprintf(
				"field %q is optional and carries a default; make it a regular field with the default arm",
				name)))
		case isDefinitionLabel(name):
			fs = append(fs, finding(field.Pos(), "definition-default", fmt.Sprintf(
				"definition %s carries a default; write the default arm at the field that uses it",
				name)))
		}
	}
	return fs
}

// hasDefaultArm reports whether e marks a default (*v), as itself or in an arm
// of the disjunctions and conjunctions it is made of.
func hasDefaultArm(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.UnaryExpr:
		return v.Op == token.MUL
	case *ast.BinaryExpr:
		return (v.Op == token.OR || v.Op == token.AND) && (hasDefaultArm(v.X) || hasDefaultArm(v.Y))
	case *ast.ParenExpr:
		return hasDefaultArm(v.X)
	}
	return false
}

// isStringDisjunction reports whether e is a disjunction whose every arm is a
// string literal, e.g. "a" | "b" | "c".
func isStringDisjunction(e ast.Expr) bool {
	bin, ok := e.(*ast.BinaryExpr)
	if !ok || bin.Op != token.OR {
		return false
	}
	return isStringArm(bin.X) && isStringArm(bin.Y)
}

func isStringArm(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Kind == token.STRING
	case *ast.BinaryExpr:
		return v.Op == token.OR && isStringArm(v.X) && isStringArm(v.Y)
	}
	return false
}

var goMapKeyRe = regexp.MustCompile(`type=map\[([^\]]+)\]`)

var cuePatternKeyRe = regexp.MustCompile(`\[(?:[A-Za-z_]\w*=)?([^\]]+)\]:`)

// lossyMapKey reports a field whose CUE map declares a constrained key but whose
// @go annotation redirects it to a plain-string Go key, dropping the grammar.
func lossyMapKey(field *ast.Field) (string, bool) {
	goKey, ok := goMapKey(field)
	if !ok || goKey != "string" {
		return "", false
	}
	cueKey, ok := cuePatternKey(field.Value)
	if !ok || cueKey == "string" {
		return "", false
	}
	return fmt.Sprintf(
		"field %q maps a constrained key %s but @go redirects to map[string]; the key grammar is lost in Go",
		labelName(field.Label), cueKey), true
}

func goMapKey(field *ast.Field) (string, bool) {
	for _, a := range field.Attrs {
		if !strings.HasPrefix(a.Text, "@go(") {
			continue
		}
		if m := goMapKeyRe.FindStringSubmatch(a.Text); m != nil {
			return m[1], true
		}
	}
	return "", false
}

func cuePatternKey(value ast.Expr) (string, bool) {
	st, ok := value.(*ast.StructLit)
	if !ok {
		return "", false
	}
	b, err := format.Node(st)
	if err != nil {
		return "", false
	}
	if m := cuePatternKeyRe.FindStringSubmatch(string(b)); m != nil {
		return strings.TrimSpace(m[1]), true
	}
	return "", false
}

func renderConstraint(e ast.Expr) string {
	b, err := format.Node(e)
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(string(b)), " ")
}

func labelName(l ast.Label) string {
	if id, ok := l.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func isDefinitionLabel(name string) bool {
	return strings.HasPrefix(name, "#") || strings.HasPrefix(name, "_#")
}

// finding spells one finding at position p.
func finding(p token.Pos, kind, msg string) string {
	return fmt.Sprintf("%s:%d: %s: %s", p.Filename(), p.Line(), kind, msg)
}
