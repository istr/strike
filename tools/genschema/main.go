// Command genschema completes the JSON Schema exports of the contract with the
// minimum a field's value sets and cue export drops (ADR-017, amendment
// 2026-11-20): for every field whose CUE value carries struct.MinFields(N), it
// writes "minProperties": N at the field's place in the exported schema, beside
// the $ref where the field refers to a definition.
//
// It runs from go generate in the contract directory, after the exports, with
// one argument per export: the schema file and the definition at its root, as
// in lane.schema.json=#Lane. It reads the CUE source of every package below
// that directory. A site is a struct.MinFields(N) with a literal N that is a
// conjunct of the value of a field. A struct.MinFields anywhere else, a site in
// a definition whose name more than one package declares, and a site whose
// place is missing from an export that holds its definition fail the
// generation. A site in a definition no export holds is not a schema site. An
// export without a site keeps the bytes cue wrote.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/parser"
	"cuelang.org/go/cue/token"
)

// site is one field that carries struct.MinFields: the definition it lies in,
// without the leading #, the field names from that definition down to the
// field, the minimum, and the position of the call.
type site struct {
	def  string
	pos  token.Pos
	path []string
	n    int
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("genschema: ")
	// os.Root confines every file the tool reads and writes to the directory
	// go generate runs it in.
	tree, err := os.OpenRoot(".")
	if err != nil {
		log.Fatal(err)
	}
	if runErr := run(tree, os.Args[1:]); runErr != nil {
		log.Fatal(runErr)
	}
}

// run places every site in the exports args names and rewrites each export
// that holds one.
func run(tree *os.Root, args []string) error {
	sites, owners, err := scan(tree.FS())
	if err != nil {
		return err
	}
	for _, s := range sites {
		if pkgs := owners[s.def]; len(pkgs) > 1 {
			return fmt.Errorf("%s: #%s is declared in the packages %s, so its place in a schema is ambiguous",
				s.pos, s.def, strings.Join(pkgs, ", "))
		}
	}
	for _, arg := range args {
		file, root, ok := strings.Cut(arg, "=#")
		if !ok || file == "" || root == "" {
			return fmt.Errorf("argument %q: want <schema file>=#<definition>", arg)
		}
		if err = complete(tree, file, root, sites); err != nil {
			return err
		}
	}
	return nil
}

// scan reads every CUE file below the root of fsys and returns its sites and,
// for every definition, the directories of the packages that declare it.
func scan(fsys fs.FS) ([]site, map[string][]string, error) {
	var sites []site
	owners := map[string][]string{}
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(name) != ".cue" {
			return err
		}
		src, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(name, src)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		found, err := fileSites(f)
		if err != nil {
			return err
		}
		sites = append(sites, found...)
		pkg := path.Dir(name)
		for _, decl := range f.Decls {
			if def, _, ok := definition(decl); ok && !slices.Contains(owners[def], pkg) {
				owners[def] = append(owners[def], pkg)
			}
		}
		return nil
	})
	return sites, owners, err
}

// fileSites returns the sites of one file. Every struct.MinFields in the file
// must be one of them; any other fails at its position.
func fileSites(f *ast.File) ([]site, error) {
	var sites []site
	for _, decl := range f.Decls {
		if def, field, ok := definition(decl); ok {
			sites = collect(sites, def, nil, field.Value)
		}
	}
	placed := map[token.Pos]bool{}
	for _, s := range sites {
		placed[s.pos] = true
	}
	var errs []error
	ast.Walk(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isMinFields(call) && !placed[call.Pos()] {
			errs = append(errs, fmt.Errorf(
				"%s: struct.MinFields is not a site: write it with a literal minimum as a conjunct of a field's value",
				call.Pos()))
		}
		return true
	}, nil)
	return sites, errors.Join(errs...)
}

// definition returns the name, without the leading #, and the field of a
// top-level definition.
func definition(decl ast.Decl) (string, *ast.Field, bool) {
	field, ok := decl.(*ast.Field)
	if !ok {
		return "", nil, false
	}
	name, _, err := ast.LabelName(field.Label)
	if err != nil || !strings.HasPrefix(name, "#") {
		return "", nil, false
	}
	return strings.TrimPrefix(name, "#"), field, true
}

// collect appends the sites of expr, the value of the field the names lead to
// from the definition def; no names is the definition's own value, which is no
// field. A struct among the conjuncts of expr holds the fields one level down.
func collect(sites []site, def string, names []string, expr ast.Expr) []site {
	for _, c := range conjuncts(expr) {
		if call, ok := c.(*ast.CallExpr); ok && isMinFields(call) {
			if n, lit := minimum(call); lit && len(names) > 0 {
				sites = append(sites, site{def: def, path: names, n: n, pos: call.Pos()})
			}
			continue
		}
		if s := structOf(c); s != nil {
			sites = collectStruct(sites, def, names, s)
		}
	}
	return sites
}

// collectStruct appends the sites of the fields of s, which the names lead to
// from the definition def. The fields of a comprehension and of an embedding are
// fields of s; a pattern constraint is no field, so a call inside it stays
// unplaced.
func collectStruct(sites []site, def string, names []string, s *ast.StructLit) []site {
	for _, elt := range s.Elts {
		switch e := elt.(type) {
		case *ast.Field:
			if name, _, err := ast.LabelName(e.Label); err == nil {
				sites = collect(sites, def, append(slices.Clip(names), name), e.Value)
			}
		case *ast.Comprehension:
			sites = collect(sites, def, names, e.Value)
		case *ast.EmbedDecl:
			sites = collect(sites, def, names, e.Expr)
		}
	}
	return sites
}

// conjuncts flattens a unification into its operands.
func conjuncts(expr ast.Expr) []ast.Expr {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		if e.Op == token.AND {
			return append(conjuncts(e.X), conjuncts(e.Y)...)
		}
	case *ast.ParenExpr:
		return conjuncts(e.X)
	}
	return []ast.Expr{expr}
}

// structOf returns the struct literal c writes, directly or through close.
func structOf(c ast.Expr) *ast.StructLit {
	if call, isCall := c.(*ast.CallExpr); isCall && len(call.Args) == 1 {
		if fn, isIdent := call.Fun.(*ast.Ident); isIdent && fn.Name == "close" {
			c = call.Args[0]
		}
	}
	s, isStruct := c.(*ast.StructLit)
	if !isStruct {
		return nil
	}
	return s
}

// isMinFields reports whether call calls struct.MinFields.
func isMinFields(call *ast.CallExpr) bool {
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel {
		return false
	}
	pkg, isIdent := sel.X.(*ast.Ident)
	name, _, err := ast.LabelName(sel.Sel)
	return isIdent && pkg.Name == "struct" && err == nil && name == "MinFields"
}

// minimum returns the literal minimum of a struct.MinFields call.
func minimum(call *ast.CallExpr) (int, bool) {
	if len(call.Args) != 1 {
		return 0, false
	}
	lit, isLit := call.Args[0].(*ast.BasicLit)
	if !isLit || lit.Kind != token.INT {
		return 0, false
	}
	n, err := strconv.Atoi(lit.Value)
	return n, err == nil
}

// complete places in the export file every site of a definition it holds --
// the definition root at the document root, every other under $defs -- and
// rewrites the file if it placed one.
func complete(tree *os.Root, file, root string, sites []site) error {
	src, err := tree.ReadFile(file)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	var doc map[string]any
	if err = dec.Decode(&doc); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	defs := object(doc["$defs"])
	placed := 0
	for _, s := range sites {
		node := object(defs[s.def])
		if s.def == root {
			node = doc
		}
		if node == nil {
			continue
		}
		at, placeErr := place(node, s.path)
		if placeErr != nil {
			return fmt.Errorf("%s: %s: #%s.%s: %w", s.pos, file, s.def, strings.Join(s.path, "."), placeErr)
		}
		at["minProperties"] = json.Number(strconv.Itoa(s.n))
		placed++
	}
	if placed == 0 {
		return nil
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	if err = enc.Encode(doc); err != nil {
		return err
	}
	return tree.WriteFile(file, out.Bytes(), 0o600)
}

// place returns the schema of the field the names lead to below node.
func place(node map[string]any, names []string) (map[string]any, error) {
	for _, name := range names {
		props := object(node["properties"])
		if props == nil {
			return nil, fmt.Errorf("the export has no properties above the field %s", name)
		}
		node = object(props[name])
		if node == nil {
			return nil, fmt.Errorf("the export has no schema for the field %s", name)
		}
	}
	return node, nil
}

// object returns v as a JSON object, or nil when it is none.
func object(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m
}
