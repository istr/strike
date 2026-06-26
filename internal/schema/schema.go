// Package schema is the single runtime home for CUE schema loading,
// compilation, and validation. It loads the embedded contract module natively
// via cue/load over an in-memory module tree and exposes JSON validation
// entry points plus the compiled package roots. Consumers hand it JSON bytes
// and receive a formatted error; the *cue.Context never leaves this package,
// because cue values are bound to the context that built them. This package
// is foundation: it imports contract and cuelang only, never internal/lane or
// internal/deploy. See docs/ADR-048-contract-type-semantics.md.
package schema

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	cuejson "cuelang.org/go/encoding/json"

	"github.com/istr/strike/contract"
)

// moduleFile is the CUE module declaration, byte-for-byte identical to the
// repository cue.mod/module.cue. It is inlined because go:embed cannot reach
// the module root from this package directory; TestModuleFileMatchesRepo
// guards against drift.
const moduleFile = `module: "github.com/istr/strike"
language: {
	version: "v0.16.0"
}
`

var (
	ctx = cuecontext.New()

	// Built once from the embedded contract at package initialization.
	deployRoot      = mustBuild("attest")
	laneRoot        = mustBuild("lane")
	crossvalRoot    = mustBuild("crossval")
	trustLayersRoot = mustBuild("trustlayers")

	// Deploy is the attest package instance: #Attestation, #Bundle, the
	// published predicates and statements, and #ArtifactRecord.
	Deploy = deployRoot
	// TrustLayers is the trustlayers package instance (the V/E/informational map).
	TrustLayers = trustLayersRoot
	// Crossval is the crossval package instance (the cross-validation vectors).
	Crossval = crossvalRoot

	// Cached definitions for the fixed validation entry points.
	laneDef        = laneRoot.LookupPath(cue.ParsePath("#Lane"))
	attestationDef = deployRoot.LookupPath(cue.ParsePath("#Attestation"))
	bundleDef      = deployRoot.LookupPath(cue.ParsePath("#Bundle"))
	provenanceDefs = map[string]cue.Value{
		"git":     laneRoot.LookupPath(cue.ParsePath("#GitProvenanceRecord")),
		"tarball": laneRoot.LookupPath(cue.ParsePath("#TarballProvenanceRecord")),
		"oci":     laneRoot.LookupPath(cue.ParsePath("#OCIProvenanceRecord")),
		"url":     laneRoot.LookupPath(cue.ParsePath("#URLProvenanceRecord")),
	}
)

// moduleRoot is a synthetic absolute path that roots the in-memory CUE module
// tree. It need not exist on disk: cue/load treats overlay entries as if their
// files -- and all their parent directories -- exist.
const moduleRoot = "/strike"

// moduleOverlay presents the embedded contract as a CUE module tree: the module
// file at <moduleRoot>/cue.mod/module.cue and the spec packages under
// <moduleRoot>/contract/. Built once at package initialization from the embedded
// files; cue/load reads it through load.Config.Overlay, so no host filesystem
// is touched.
var moduleOverlay = buildModuleOverlay()

func buildModuleOverlay() map[string]load.Source {
	overlay := map[string]load.Source{
		moduleRoot + "/cue.mod/module.cue": load.FromString(moduleFile),
	}
	walkErr := fs.WalkDir(contract.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".cue") {
			return nil
		}
		data, rerr := fs.ReadFile(contract.FS, p)
		if rerr != nil {
			return rerr
		}
		overlay[moduleRoot+"/contract/"+p] = load.FromBytes(data)
		return nil
	})
	if walkErr != nil {
		panic(fmt.Sprintf("schema: walk contract fs: %v", walkErr))
	}
	return overlay
}

// mustBuild loads and builds one contract package instance. It panics on
// failure: a contract module that does not load is a build-time defect, not a
// runtime condition.
func mustBuild(pkg string) cue.Value {
	insts := load.Instances([]string{"./contract/" + pkg}, &load.Config{Dir: moduleRoot, Overlay: moduleOverlay})
	if len(insts) != 1 {
		panic(fmt.Sprintf("schema: load %q: expected 1 instance, got %d", pkg, len(insts)))
	}
	if err := insts[0].Err; err != nil {
		panic(fmt.Sprintf("schema: load %q: %v", pkg, err))
	}
	v := ctx.BuildInstance(insts[0])
	if err := v.Err(); err != nil {
		panic(fmt.Sprintf("schema: build %q: %v", pkg, err))
	}
	return v
}

// ValidateLaneJSON validates lane JSON (converted from YAML) against #Lane.
func ValidateLaneJSON(data []byte) error {
	expr, err := cuejson.Extract("lane.yaml", data)
	if err != nil {
		return err
	}
	unified := laneDef.Unify(ctx.BuildExpr(expr))
	return FormatValidationError(unified.Validate(cue.Concrete(true)))
}

// ValidateAttestationJSON validates a serialized attestation against
// #Attestation. This is the cross-validation boundary: any implementation can
// serialize an attestation to JSON and validate it against the same schema.
func ValidateAttestationJSON(data []byte) error {
	expr, err := cuejson.Extract("attestation.json", data)
	if err != nil {
		return fmt.Errorf("extract attestation JSON: %w", err)
	}
	unified := attestationDef.Unify(ctx.BuildExpr(expr))
	if err := FormatValidationError(unified.Validate(cue.Concrete(true))); err != nil {
		return fmt.Errorf("attestation schema violation:\n%w", err)
	}
	return nil
}

// ValidateBundleJSON validates a marshaled sigstore bundle against #Bundle.
func ValidateBundleJSON(data []byte) error {
	expr, err := cuejson.Extract("bundle.json", data)
	if err != nil {
		return fmt.Errorf("extract bundle JSON: %w", err)
	}
	unified := bundleDef.Unify(ctx.BuildExpr(expr))
	if err := FormatValidationError(unified.Validate(cue.Concrete(true))); err != nil {
		return fmt.Errorf("bundle schema violation:\n%w", err)
	}
	return nil
}

// ValidateProvenanceJSON validates a provenance record against the schema for
// declaredType. It performs the schema-side checks only (unknown type, JSON
// shape, type-field match, and constraint unification); the typed unmarshal
// into the lane record types stays in internal/lane, preserving the rule that
// this foundation package does not import internal/lane.
func ValidateProvenanceJSON(declaredType string, raw []byte) error {
	def, ok := provenanceDefs[declaredType]
	if !ok {
		return fmt.Errorf("unknown provenance type %q", declaredType)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("not valid JSON: %w", err)
	}
	recordType, ok := probe["type"].(string)
	if !ok {
		return fmt.Errorf("provenance record field \"type\" is not a string")
	}
	if recordType != declaredType {
		return fmt.Errorf("record type %q does not match declared type %q", recordType, declaredType)
	}
	rec := ctx.CompileBytes(raw)
	if rec.Err() != nil {
		return fmt.Errorf("invalid record: %w", rec.Err())
	}
	unified := def.Unify(rec)
	if err := unified.Validate(cue.Concrete(true)); err != nil {
		return fmt.Errorf("schema validation: %w", err)
	}
	return nil
}

// ValidateDef validates raw JSON against a named definition in one of the
// exported roots (Deploy, Crossval, TrustLayers). Extraction and unification
// run inside this package's context, which is required because the root and
// the extracted expression must share a context.
func ValidateDef(root cue.Value, def string, data []byte) error {
	d := root.LookupPath(cue.ParsePath(def))
	expr, err := cuejson.Extract("data.json", data)
	if err != nil {
		return fmt.Errorf("extract %s JSON: %w", def, err)
	}
	unified := d.Unify(ctx.BuildExpr(expr))
	return FormatValidationError(unified.Validate(cue.Concrete(true)))
}
