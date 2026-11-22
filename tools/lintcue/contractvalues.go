package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/build"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/token"
)

// emptyValues are the four values no field holds (ADR-049 rule 6), in the order
// a finding names them.
var emptyValues = [...]string{`""`, "null", "[]", "{}"}

// valueWalk walks the evaluated definitions of one contract package. It records
// the empty values each site accepts, with the position a finding there
// reports, and the union-arm findings.
type valueWalk struct {
	accepts  map[string]uint8
	pos      map[string]token.Pos
	empties  []cue.Value
	findings []string
}

// valueFindings runs the lints that read the evaluated value of every contract
// package (ADR-049 rules 6 and 7): every site that accepts an empty value and
// that neither a deferral nor an exemption names with exactly those values,
// every deferral and exemption that matches no such site, and every union with
// an arm that is not a named definition. A deferral and an exemption are
// spelled "<dir> <site> accepts <values>", and deferrals are keyed by the item
// that owns the change. A value the walk cannot classify aborts the run.
func valueFindings(insts map[string]*build.Instance, deferrals map[string][]string, exemptions []string) ([]string, error) {
	ctx := cuecontext.New()
	empties := compileEmpties(ctx)
	// allowed maps every deferred or exempt site to whether a finding matched it.
	allowed := map[string]bool{}
	for _, sites := range deferrals {
		for _, s := range sites {
			allowed[s] = false
		}
	}
	for _, s := range exemptions {
		allowed[s] = false
	}
	var fs []string
	for _, dir := range slices.Sorted(maps.Keys(insts)) {
		v := ctx.BuildInstance(insts[dir])
		if err := v.Err(); err != nil {
			return nil, fmt.Errorf("build contract/%s: %w", dir, err)
		}
		w, err := walkDefinitions(v, empties)
		if err != nil {
			return nil, fmt.Errorf("contract/%s: %w", dir, err)
		}
		fs = append(fs, w.findings...)
		fs = appendEmptyFindings(fs, dir, w, allowed)
	}
	for owner, sites := range deferrals {
		for _, s := range sites {
			if !allowed[s] {
				fs = append(fs, staleFinding("stale-deferral", s, "is deferred to "+owner))
			}
		}
	}
	for _, s := range exemptions {
		if !allowed[s] {
			fs = append(fs, staleFinding("stale-exemption", s, "is exempt"))
		}
	}
	return fs, nil
}

// staleFinding spells a deferral or an exemption, s, that matches no finding.
func staleFinding(kind, s, state string) string {
	dir, site, _ := strings.Cut(s, " ")
	return fmt.Sprintf("contract/%s: %s: %s %s but matches no finding", dir, kind, site, state)
}

// compileEmpties compiles the four empty values in ctx.
func compileEmpties(ctx *cue.Context) []cue.Value {
	vs := make([]cue.Value, len(emptyValues))
	for i, e := range emptyValues {
		vs[i] = ctx.CompileString(e)
	}
	return vs
}

// walkDefinitions walks every definition of the package value v.
func walkDefinitions(v cue.Value, empties []cue.Value) (*valueWalk, error) {
	w := &valueWalk{accepts: map[string]uint8{}, pos: map[string]token.Pos{}, empties: empties}
	it, err := v.Fields(cue.Definitions(true))
	if err != nil {
		return nil, fmt.Errorf("list definitions: %w", err)
	}
	for it.Next() {
		if !it.Selector().IsDefinition() {
			continue
		}
		name := it.Selector().String()
		if err = w.enter(name, it.Value(), it.Value().Pos()); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// enter descends into v at site. A value of type _ and a scalar end the descent,
// and so does a bare reference: the definition it names is walked as itself. A
// union is not entered. A struct or a list written inline, and a composition
// with a definition, are entered. pos is the position a finding at site reports
// when v has none of its own. A value of no kind that no conjunct makes a
// scalar is entered by enterNoKind. A value of struct and list kind outside a
// union cannot be classified, and the walk stops with an error.
func (w *valueWalk) enter(site string, v cue.Value, pos token.Pos) error {
	if p := v.Pos(); p.IsValid() {
		pos = p
	}
	kind := v.IncompleteKind()
	switch {
	case kind == cue.BottomKind && !hasScalarConjunct(v):
		return w.enterNoKind(site, v, pos)
	case kind == cue.TopKind, kind&(cue.StructKind|cue.ListKind) == 0, isReference(v):
		return nil
	}
	if w.union(site, v, pos) {
		return nil
	}
	switch {
	case kind&cue.ListKind == 0:
		return w.enterStruct(site, v, pos)
	case kind&cue.StructKind == 0:
		return w.enterList(site, v, pos)
	}
	return fmt.Errorf("%s:%d: %s is both a struct and a list outside a union, which the walk cannot classify",
		pos.Filename(), pos.Line(), site)
}

// enterNoKind enters v, a value of no kind, as a struct when it lists a field
// or a pattern. A struct under struct.MinFields(1) lists its fields, and so does
// a struct whose comprehension reads a field the schema leaves open; a field
// such a comprehension adds is not listed, and the walk does not see it. A value
// that lists nothing cannot be classified, and the walk stops with an error.
func (w *valueWalk) enterNoKind(site string, v cue.Value, pos token.Pos) error {
	it, err := v.Fields(cue.Optional(true), cue.Patterns(true))
	if err != nil {
		return fmt.Errorf("%s:%d: %s: %w", pos.Filename(), pos.Line(), site, err)
	}
	if !it.Next() {
		return fmt.Errorf("%s:%d: %s has a value of no kind, which the walk cannot classify",
			pos.Filename(), pos.Line(), site)
	}
	return w.enterStruct(site, v, pos)
}

// hasScalarConjunct reports whether v is a conjunction one of whose conjuncts
// has a kind that admits neither a struct nor a list. Such a value is a scalar
// even when it has no kind of its own, as a value indexed by a field the schema
// leaves open has none.
func hasScalarConjunct(v cue.Value) bool {
	op, args := v.Expr()
	if op != cue.AndOp {
		return false
	}
	for _, a := range args {
		if k := a.IncompleteKind(); k != cue.BottomKind && k&(cue.StructKind|cue.ListKind) == 0 {
			return true
		}
	}
	return false
}

// isReference reports whether v is a bare reference to another value.
func isReference(v cue.Value) bool {
	_, path := v.ReferencePath()
	return len(path.Selectors()) > 0
}

// union reports whether v is a union, or a conjunction that holds one, and
// records a union-arm finding at site for a union with an arm that is not a
// reference to a definition. A union is not entered: each of its arms is a
// named definition and is walked as itself.
func (w *valueWalk) union(site string, v cue.Value, pos token.Pos) bool {
	op, args := v.Expr()
	switch op {
	case cue.OrOp:
		for _, arm := range args {
			_, path := arm.ReferencePath()
			sels := path.Selectors()
			if len(sels) == 0 || !sels[len(sels)-1].IsDefinition() {
				w.findings = append(w.findings, finding(pos, "union-arm",
					site+" is a union with an arm that is not a named definition"))
				break
			}
		}
		return true
	case cue.AndOp:
		found := false
		for _, a := range args {
			if a.IncompleteKind()&(cue.StructKind|cue.ListKind) != 0 && !isReference(a) && w.union(site, a, pos) {
				found = true
			}
		}
		return found
	default:
		return false
	}
}

// enterStruct checks and enters every field of the struct v, and every entry
// beyond its declared fields: those of a pattern of any key, and the open
// remainder. An entry is spelled [_], so entries from several sources are one
// site.
func (w *valueWalk) enterStruct(site string, v cue.Value, pos token.Pos) error {
	it, err := v.Fields(cue.Optional(true), cue.Patterns(true))
	if err != nil {
		return fmt.Errorf("%s:%d: %s: %w", pos.Filename(), pos.Line(), site, err)
	}
	for it.Next() {
		sub := site + ".[_]"
		if sel := it.Selector(); sel.ConstraintType() != cue.PatternConstraint {
			sub = site + "." + cue.Str(sel.Unquoted()).String()
		}
		if err = w.field(sub, it.Value(), pos); err != nil {
			return err
		}
	}
	if rest := v.LookupPath(cue.MakePath(cue.AnyString)); rest.Exists() {
		return w.field(site+".[_]", rest, pos)
	}
	return nil
}

// field checks v at site against the empty values, then enters it.
func (w *valueWalk) field(site string, v cue.Value, pos token.Pos) error {
	if p := v.Pos(); p.IsValid() {
		pos = p
	}
	for i, empty := range w.empties {
		if v.Unify(empty).Validate(cue.Concrete(true)) != nil {
			continue
		}
		if _, seen := w.accepts[site]; !seen {
			w.pos[site] = pos
		}
		w.accepts[site] |= 1 << i
	}
	return w.enter(site, v, pos)
}

// enterList enters every element of the list v, the prefix elements and the
// elements beyond them, without checking it: a list element is not a field
// (ADR-049 rule 6). Every element is spelled [_].
func (w *valueWalk) enterList(site string, v cue.Value, pos token.Pos) error {
	it, err := v.Fields(cue.Optional(true), cue.Patterns(true))
	if err != nil {
		return fmt.Errorf("%s:%d: %s: %w", pos.Filename(), pos.Line(), site, err)
	}
	for it.Next() {
		if err = w.enter(site+".[_]", it.Value(), pos); err != nil {
			return err
		}
	}
	return nil
}

// appendEmptyFindings reports every site of w in package dir that accepts an
// empty value unless allowed holds it, spelled "<dir> <site> accepts
// <values>", and marks every entry of allowed it matches.
func appendEmptyFindings(fs []string, dir string, w *valueWalk, allowed map[string]bool) []string {
	for path, set := range w.accepts {
		var vals []string
		for i, e := range emptyValues {
			if set&(1<<i) != 0 {
				vals = append(vals, e)
			}
		}
		spelled := path + " accepts " + strings.Join(vals, " ")
		if _, ok := allowed[dir+" "+spelled]; ok {
			allowed[dir+" "+spelled] = true
			continue
		}
		fs = append(fs, finding(w.pos[path], "empty-value", spelled))
	}
	return fs
}
