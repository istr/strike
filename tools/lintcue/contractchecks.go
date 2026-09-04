package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/format"
	"cuelang.org/go/cue/load"
	"cuelang.org/go/cue/token"
)

// contractSyntaxFindings runs the CUE-source lints over contract/: inline string
// disjunctions (ADR-049 rule 5), re-inlined primitive grammars, and lossy @go
// map-key redirects. These are properties of how the schema is written, so they
// read the CUE syntax rather than the evaluated value.
func contractSyntaxFindings(root string) ([]string, error) {
	files, err := contractFiles(root)
	if err != nil {
		return nil, err
	}
	prims := primitiveConstraints(root)
	var findings []string
	for _, f := range files {
		ast.Walk(f, func(n ast.Node) bool {
			if field, ok := n.(*ast.Field); ok {
				findings = appendFieldFindings(findings, field, prims)
			}
			return true
		}, nil)
	}
	return findings, nil
}

// contractFiles parses every .cue file under contract/, one load per package
// directory (mirroring the coverage loader), and returns the syntax trees.
func contractFiles(root string) ([]*ast.File, error) {
	entries, err := os.ReadDir(filepath.Join(root, "contract"))
	if err != nil {
		return nil, fmt.Errorf("read contract dir: %w", err)
	}
	var files []*ast.File
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		insts := load.Instances(
			[]string{"./contract/" + e.Name()}, &load.Config{Dir: root})
		for _, inst := range insts {
			if inst.Err != nil {
				continue
			}
			files = append(files, inst.Files...)
		}
	}
	return files, nil
}

// primitiveConstraints maps the normalized source of each primitive definition
// constraint to its name, so a re-inlined grammar can be matched back to the
// primitive that already owns it.
func primitiveConstraints(root string) map[string]string {
	out := map[string]string{}
	insts := load.Instances(
		[]string{"./contract/primitive"}, &load.Config{Dir: root})
	for _, inst := range insts {
		if inst.Err != nil {
			continue
		}
		for _, f := range inst.Files {
			for _, d := range f.Decls {
				field, ok := d.(*ast.Field)
				if !ok {
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
	}
	return out
}

func appendFieldFindings(fs []string, field *ast.Field, prims map[string]string) []string {
	name := labelName(field.Label)
	if !isDefinitionLabel(name) && isStringDisjunction(field.Value) {
		fs = append(fs, finding(field, "inline-string-disjunction", fmt.Sprintf(
			"field %q inlines a string disjunction; define a named type and reference it (ADR-049 rule 5)",
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
