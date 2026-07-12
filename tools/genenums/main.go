// Command genenums post-processes the CUE-to-Go type generation. For each
// contract package it moves the gengotypes output into that package's internal
// Go home with the contract import prefix rewritten to internal, and it emits
// the sibling enum constant block that gengotypes drops (a string-disjunction
// definition yields the named type but not its values). Public CUE API only
// (cue/load + cue) plus go/format; it spawns no process -- gengotypes and the
// cue exports run as separate go:generate directives.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: genenums <contract-package-name>...")
	}
	root, err := moduleRoot()
	if err != nil {
		log.Fatalf("genenums: %v", err)
	}
	// os.Root confines every file the tool touches to the module tree; it is
	// also the sanitization point for gosec's path-taint analysis, since the
	// paths derive from command-line package names.
	tree, err := os.OpenRoot(root)
	if err != nil {
		log.Fatalf("genenums: %v", err)
	}
	for _, name := range os.Args[1:] {
		if moveErr := move(tree, name); moveErr != nil {
			log.Fatalf("genenums move: %v", moveErr)
		}
		if enumErr := emitEnums(tree, name); enumErr != nil {
			log.Fatalf("genenums enums: %v", enumErr)
		}
	}
}

// moduleRoot walks up from the working directory to the directory holding
// go.mod, so the tool is independent of the directory go:generate runs it in.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above working directory")
		}
		dir = parent
	}
}

// internalDir maps a contract package name to its generated Go home and package
// name. attest's Go home is the hand-written deploy package.
func internalDir(name string) (dir, pkg string) {
	if name == "attest" {
		return "internal/deploy", "deploy"
	}
	return "internal/" + name, name
}

// move rewrites one gengotypes output (contract/<name>/cue_types_gen.go) into
// its internal Go home. The contract import prefix is rewritten to internal for
// every package; attest additionally takes the package rename and the
// bogus-bare-import repair that gengotypes' cross-package @go overrides need.
func move(tree *os.Root, name string) error {
	src := filepath.Join("contract", name, "cue_types_gen.go")
	b, err := tree.ReadFile(src)
	if err != nil {
		return err
	}
	b = bytes.ReplaceAll(b,
		[]byte("github.com/istr/strike/contract/"),
		[]byte("github.com/istr/strike/internal/"))
	if name == "attest" {
		if b, err = fixAttest(b); err != nil {
			return err
		}
	}
	dir, _ := internalDir(name)
	if err = tree.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err = tree.WriteFile(filepath.Join(dir, name+".gen.go"), b, 0o600); err != nil {
		return err
	}
	return tree.Remove(src)
}

// fixAttest renames the package to deploy and repairs the bare imports
// gengotypes emits for cross-package @go(,type=map[pkg.K]V) overrides: the
// endpoint and primitive bare lines duplicate a real import and are dropped;
// the lane and record bare lines are the only source of their import and are
// rewritten to the real path. The result is gofmt-normalized.
func fixAttest(b []byte) ([]byte, error) {
	lines := strings.Split(string(b), "\n")
	out := make([]string, 0, len(lines))
	renamed := false
	for _, ln := range lines {
		switch {
		case !renamed && ln == "package attest":
			out = append(out, "package deploy")
			renamed = true
		case ln == "\t\"endpoint\"", ln == "\t\"primitive\"":
			// drop: duplicates a real import already in the block
		case ln == "\t\"lane\"":
			out = append(out, "\t\"github.com/istr/strike/internal/lane\"")
		case ln == "\t\"record\"":
			out = append(out, "\t\"github.com/istr/strike/internal/record\"")
		default:
			out = append(out, ln)
		}
	}
	return format.Source([]byte(strings.Join(out, "\n")))
}

type enumDef struct {
	goType string
	values []string
}

// emitEnums recovers each string-disjunction definition's values as unexported
// typed constants beside the moved types, so switches over the type can be
// exhaustiveness-checked. It writes nothing when a package has no such def.
func emitEnums(tree *os.Root, name string) error {
	ctx := cuecontext.New()
	insts := load.Instances([]string{"./contract/" + name}, &load.Config{Dir: tree.Name()})
	if len(insts) == 0 {
		return fmt.Errorf("no instances")
	}
	if insts[0].Err != nil {
		return insts[0].Err
	}
	pkgVal := ctx.BuildInstance(insts[0])
	if err := pkgVal.Err(); err != nil {
		return err
	}
	defs, err := collectEnums(pkgVal)
	if err != nil {
		return err
	}
	if len(defs) == 0 {
		return nil
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].goType < defs[j].goType })
	dir, pkg := internalDir(name)
	formatted, err := format.Source(render(pkg, defs))
	if err != nil {
		return fmt.Errorf("format: %w", err)
	}
	return tree.WriteFile(filepath.Join(dir, filepath.Base(dir)+"_enum.gen.go"), formatted, 0o600)
}

func collectEnums(pkgVal cue.Value) ([]enumDef, error) {
	iter, err := pkgVal.Fields(cue.Definitions(true))
	if err != nil {
		return nil, err
	}
	var defs []enumDef
	for iter.Next() {
		sel := iter.Selector()
		if !sel.IsDefinition() {
			continue
		}
		v := iter.Value()
		vals, ok := stringDisjuncts(v)
		if !ok {
			continue
		}
		defs = append(defs, enumDef{values: vals, goType: goTypeName(sel, v)})
	}
	return defs, nil
}

// stringDisjuncts returns the concrete string disjuncts of v if v is a
// disjunction of concrete strings (with or without a default marker).
func stringDisjuncts(v cue.Value) (vals []string, ok bool) {
	op, args := v.Expr()
	if op != cue.OrOp || len(args) < 2 {
		return nil, false
	}
	for _, a := range args {
		if a.Kind() != cue.StringKind {
			return nil, false
		}
		s, err := a.String()
		if err != nil {
			return nil, false
		}
		vals = append(vals, s)
	}
	return vals, true
}

// goTypeName derives the Go type name gengotypes emits for the def: the @go
// attribute name if present, else the definition name without its leading '#'.
func goTypeName(sel cue.Selector, v cue.Value) string {
	if a := v.Attribute("go"); a.Err() == nil {
		if name, err := a.String(0); err == nil && name != "" {
			return name
		}
	}
	return strings.TrimPrefix(sel.String(), "#")
}

func render(pkg string, defs []enumDef) []byte {
	var b strings.Builder
	b.WriteString("// Code generated by genenums. DO NOT EDIT.\n\n")
	b.WriteString("package " + pkg + "\n\n")
	b.WriteString("const (\n")
	for _, d := range defs {
		for _, val := range d.values {
			b.WriteString("\t" + constIdent(d.goType, val) + " " + d.goType + " = " + strconv.Quote(val) + "\n")
		}
	}
	b.WriteString(")\n")
	return []byte(b.String())
}

// constIdent builds the exported constant identifier: goType plus
// the CamelCased value. "spdx-json" -> "SpdxJson"; "file" -> "File".
func constIdent(goType, val string) string {
	return goType + camel(val)
}

func camel(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' })
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		r := []rune(p)
		r[0] = unicode.ToUpper(r[0])
		b.WriteString(string(r))
	}
	return b.String()
}
