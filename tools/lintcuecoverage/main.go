// Command lintcuecoverage fails when a hand-written Go type ought to be a
// generated CUE type. A named type is reported when it is not declared in a
// generated file, is not behavioral, and any of the following holds: it shares
// its name with a CUE definition under contract/; it carries a json-tagged
// struct field; or another package refers to it. A behavioral type is an
// interface, function, or channel type, or a struct holding a field that is one
// of those or a sync/os handle. The tree must compile for the report to be
// meaningful, so the command aborts when the package loader reports any error.
package main

import (
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	"golang.org/x/tools/go/packages"
)

const modulePrefix = "github.com/istr/strike/"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: lintcuecoverage <package-pattern>...")
		os.Exit(2)
	}
	findings, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, f := range findings {
		fmt.Fprintln(os.Stderr, f)
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
}

func run(patterns []string) ([]string, error) {
	cueNames, err := cueGoTypeNames(".")
	if err != nil {
		return nil, fmt.Errorf("read cue definitions: %w", err)
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports |
			packages.NeedDeps,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	if n := countLoadErrors(pkgs); n > 0 {
		return nil, fmt.Errorf(
			"tree does not compile: %d load error(s); coverage lint needs a buildable tree", n)
	}
	used := crossPackageUses(pkgs)
	var findings []string
	for _, p := range pkgs {
		if strings.HasPrefix(p.PkgPath, modulePrefix) && p.Types != nil {
			findings = appendFindings(findings, p, cueNames, used)
		}
	}
	sort.Strings(findings)
	return findings, nil
}

func appendFindings(findings []string, p *packages.Package,
	cueNames map[string]bool, used map[types.Object]map[string]bool,
) []string {
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || tn.IsAlias() {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		pos := p.Fset.Position(tn.Pos())
		if strings.HasSuffix(pos.Filename, ".gen.go") || behavioralNamed(named) {
			continue
		}
		if !required(named, name, cueNames) &&
			!referencedCrossPackage(tn, p.PkgPath, used) {
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"%s: %s.%s is hand-written but must be a generated CUE type",
			pos, strings.TrimPrefix(p.PkgPath, modulePrefix), name))
	}
	return findings
}

// required reports whether a type must be surfaced in CUE on its own account:
// its name is a CUE definition, or it is a serialized struct.
func required(named *types.Named, name string, cueNames map[string]bool) bool {
	if cueNames[name] {
		return true
	}
	st, ok := named.Underlying().(*types.Struct)
	return ok && hasJSONField(st)
}

func hasJSONField(st *types.Struct) bool {
	for i := 0; i < st.NumFields(); i++ {
		if _, ok := reflect.StructTag(st.Tag(i)).Lookup("json"); ok {
			return true
		}
	}
	return false
}

func behavioralNamed(n *types.Named) bool {
	switch u := n.Underlying().(type) {
	case *types.Interface, *types.Signature, *types.Chan:
		return true
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if behavioralField(u.Field(i).Type()) {
				return true
			}
		}
	}
	return false
}

func behavioralField(t types.Type) bool {
	for {
		ptr, ok := t.(*types.Pointer)
		if !ok {
			break
		}
		t = ptr.Elem()
	}
	switch t.Underlying().(type) {
	case *types.Interface, *types.Signature, *types.Chan:
		return true
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	switch named.Obj().Pkg().Path() {
	case "sync", "sync/atomic", "os":
		return true
	}
	return false
}

func countLoadErrors(pkgs []*packages.Package) int {
	n := 0
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		n += len(p.Errors)
	})
	return n
}

func crossPackageUses(pkgs []*packages.Package) map[types.Object]map[string]bool {
	used := map[types.Object]map[string]bool{}
	for _, p := range pkgs {
		if p.TypesInfo == nil {
			continue
		}
		for _, obj := range p.TypesInfo.Uses {
			tn, ok := obj.(*types.TypeName)
			if !ok || tn.Pkg() == nil {
				continue
			}
			if used[tn] == nil {
				used[tn] = map[string]bool{}
			}
			used[tn][p.PkgPath] = true
		}
	}
	return used
}

func referencedCrossPackage(tn *types.TypeName, defPkg string,
	used map[types.Object]map[string]bool,
) bool {
	for u := range used[tn] {
		if u != defPkg {
			return true
		}
	}
	return false
}

// cueGoTypeNames returns the Go type names of every definition in every CUE
// package under root/contract, following @go type-name redirects. It mirrors
// the load pattern in internal/schema. A package that fails to load is skipped
// rather than fatal: a missing name only weakens the report, never corrupts it.
func cueGoTypeNames(root string) (map[string]bool, error) {
	names := map[string]bool{}
	ctx := cuecontext.New()
	entries, err := os.ReadDir(filepath.Join(root, "contract"))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		insts := load.Instances(
			[]string{"./contract/" + e.Name()}, &load.Config{Dir: root})
		if len(insts) == 0 || insts[0].Err != nil {
			continue
		}
		v := ctx.BuildInstance(insts[0])
		if v.Err() != nil {
			continue
		}
		collectDefNames(v, names)
	}
	return names, nil
}

func collectDefNames(v cue.Value, names map[string]bool) {
	it, err := v.Fields(cue.Definitions(true))
	if err != nil {
		return
	}
	for it.Next() {
		goName := strings.TrimPrefix(strings.TrimPrefix(it.Selector().String(), "_#"), "#")
		if attr := it.Value().Attribute("go"); attr.Err() == nil {
			if s, err := attr.String(0); err == nil && s != "" {
				if s == "-" {
					continue
				}
				goName = s
			}
		}
		names[goName] = true
	}
}
