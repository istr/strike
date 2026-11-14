package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"cuelang.org/go/cue/ast"
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

// contractSyntaxFindings runs the CUE-source lints over contract/: inline string
// disjunctions (ADR-049 rule 5), re-inlined primitive grammars, lossy @go
// map-key redirects, and imports that break the tier order. These are
// properties of how the schema is written, so they read the CUE syntax rather
// than the evaluated value.
func contractSyntaxFindings(root string) ([]string, error) {
	pkgs, err := contractFiles(root)
	if err != nil {
		return nil, err
	}
	prims := primitiveConstraints(pkgs["primitive"])
	var findings []string
	for dir, files := range pkgs {
		findings = appendTierFindings(findings, dir, files)
		for _, f := range files {
			ast.Walk(f, func(n ast.Node) bool {
				if field, ok := n.(*ast.Field); ok {
					findings = appendFieldFindings(findings, field, prims)
				}
				return true
			}, nil)
		}
	}
	sort.Strings(findings)
	return findings, nil
}

// contractFiles loads every package directory under contract/ and returns its
// syntax trees keyed by directory name. A package that fails to load aborts the
// run: a lint that skips what it cannot read reports a tree it has not seen as
// clean.
func contractFiles(root string) (map[string][]*ast.File, error) {
	entries, err := os.ReadDir(filepath.Join(root, "contract"))
	if err != nil {
		return nil, fmt.Errorf("read contract dir: %w", err)
	}
	pkgs := map[string][]*ast.File{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		insts := load.Instances(
			[]string{"./contract/" + e.Name()}, &load.Config{Dir: root})
		for _, inst := range insts {
			if inst.Err != nil {
				return nil, fmt.Errorf("load contract/%s: %w", e.Name(), inst.Err)
			}
			pkgs[e.Name()] = append(pkgs[e.Name()], inst.Files...)
		}
	}
	return pkgs, nil
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
			name, isContract := strings.CutPrefix(path, contractPrefix)
			to, declared := contractTiers[name]
			switch {
			case !isContract || !declared:
				fs = append(fs, finding(spec, "undeclared-tier", fmt.Sprintf(
					"package %s imports %q, which is not a contract package with a declared tier",
					dir, path)))
			case to >= tier:
				fs = append(fs, finding(spec, "tier-direction", fmt.Sprintf(
					"package %s (%s tier) imports %s (%s tier); a contract package imports only from a strictly lower tier",
					dir, tierNames[tier], name, tierNames[to])))
			}
		}
	}
	return fs
}

func appendFieldFindings(fs []string, field *ast.Field, prims map[string]string) []string {
	name := labelName(field.Label)
	// ADR-049 rule 5: a string disjunction is a named type, never inline.
	if !isDefinitionLabel(name) && isStringDisjunction(field.Value) {
		fs = append(fs, finding(field, "inline-string-disjunction", fmt.Sprintf(
			"field %q inlines a string disjunction; define a named type and reference it",
			name)))
	}
	if !isDefinitionLabel(name) {
		if prim, ok := prims[renderConstraint(field.Value)]; ok && prim != name {
			fs = append(fs, finding(field, "primitive-reuse", fmt.Sprintf(
				"field %q re-inlines the grammar of primitive %s; reference %s instead",
				name, prim, prim)))
		}
	}
	if msg, ok := lossyMapKey(field); ok {
		fs = append(fs, finding(field, "lossy-map-key", msg))
	}
	return fs
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

func finding(n ast.Node, kind, msg string) string {
	p := n.Pos()
	return fmt.Sprintf("%s:%d: %s: %s", p.Filename(), p.Line(), kind, msg)
}
