package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/token"
)

const contractImportPrefix = "github.com/istr/strike/contract/"

// packageTiers is the layer order of the contract value packages
// (docs/SPEC-PACKAGE-LAYERING.md): primitive is the vocabulary, the concept
// packages (endpoint, output, provenance, record) compose it, lane is the
// wire format that composes concepts, attest is the output wire that attests
// a lane run. An import is legal only when it points strictly down this
// order; a value package never imports upward or sideways.
var packageTiers = map[string]int{
	"primitive":  0,
	"endpoint":   1,
	"output":     1,
	"provenance": 1,
	"record":     1,
	"lane":       2,
	"attest":     3,
}

// consumerImports lists the contract packages that consume value packages to
// classify or cross-check them rather than to compose them, and the value
// packages each may import. crossval constrains vector inputs with the same
// lane and endpoint types the product enforces; trustlayers single-sources
// its vocabulary from record. Everything outside a consumer's allowlist is
// closed to it, including attest: input-side checking embeds no output-side
// attestation.
var consumerImports = map[string]map[string]bool{
	"crossval":    {"primitive": true, "endpoint": true, "lane": true},
	"trustlayers": {"record": true},
}

// contractGateFindings runs the tree-wide contract gates over contract/:
// cross-package imports must point down the tier order, and a list field
// declared without the optional marker must be written in the non-empty
// form. Both are properties of the schema's declared meaning, so they read
// the CUE syntax, like contractSyntaxFindings.
func contractGateFindings(root string) ([]string, error) {
	files, err := contractFiles(root)
	if err != nil {
		return nil, err
	}
	var findings []string
	for _, f := range files {
		findings = appendImportFindings(findings, f)
		findings = appendRequiredListFindings(findings, f)
	}
	return findings, nil
}

// appendImportFindings reports every cross-package import that points up the
// tier order or outside its consumer allowlist. Intra-package references have
// no direction, and CUE itself already guarantees acyclicity; the gate adds
// the tier order on top.
func appendImportFindings(fs []string, f *ast.File) []string {
	own := f.PackageName()
	for _, d := range f.Decls {
		imp, ok := d.(*ast.ImportDecl)
		if !ok {
			continue
		}
		for _, spec := range imp.Specs {
			if msg := importFinding(own, spec); msg != "" {
				fs = append(fs, finding(spec, "tier-direction", msg))
			}
		}
	}
	return fs
}

// importFinding returns the tier-direction violation message for one import
// spec, or "" when the import is legal: outside the contract module,
// intra-package, down the tier order, or inside a consumer's allowlist.
func importFinding(own string, spec *ast.ImportSpec) string {
	path, err := strconv.Unquote(spec.Path.Value)
	if err != nil || !strings.HasPrefix(path, contractImportPrefix) {
		return ""
	}
	target := strings.TrimPrefix(path, contractImportPrefix)
	if target == own {
		return ""
	}
	if allowed, ok := consumerImports[own]; ok {
		if !allowed[target] {
			return fmt.Sprintf(
				"package %q imports %q outside its allowlist %v",
				own, target, sortedKeys(allowed))
		}
		return ""
	}
	ownTier, ok := packageTiers[own]
	if !ok {
		return ""
	}
	targetTier, ok := packageTiers[target]
	if !ok {
		return ""
	}
	if targetTier >= ownTier {
		return fmt.Sprintf(
			"package %q (tier %d) imports %q (tier %d); imports must point strictly down the tier order",
			own, ownTier, target, targetTier)
	}
	return ""
}

// appendRequiredListFindings reports a field declared without the optional
// marker whose list is the open form [...T]: CUE gives such a list the empty
// default, and the JSON Schema export drops defaulted fields from required,
// so a non-optional field written open is not really required. Either mark
// the field optional (x?:), or write the non-empty form [T, ...T] that
// contract/lane already uses for steps. Pattern-label fields are exempt:
// their value is a map's per-key shape, not a list field.
func appendRequiredListFindings(fs []string, f *ast.File) []string {
	ast.Walk(f, func(n ast.Node) bool {
		field, ok := n.(*ast.Field)
		if !ok {
			return true
		}
		if field.Constraint == token.OPTION {
			return true
		}
		if _, isIdent := field.Label.(*ast.Ident); !isIdent {
			return true
		}
		list, ok := field.Value.(*ast.ListLit)
		if !ok || len(list.Elts) == 0 {
			return true
		}
		if _, open := list.Elts[0].(*ast.Ellipsis); open {
			fs = append(fs, finding(field, "required-list", fmt.Sprintf(
				"field %q is declared without the optional marker but written as an open list; mark it optional (?:) or use the non-empty form [T, ...T]",
				labelName(field.Label))))
		}
		return true
	}, nil)
	return fs
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
