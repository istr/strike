package lane

import (
	"fmt"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/istr/strike/internal/endpoint"
	"github.com/istr/strike/internal/primitive"
)

// registryHosts is the lane's registry declarations by written authority: the
// registries a reference may name, each storage with the registry whose
// redirect alone reaches it, and each deploy target with the steps that push
// to it. A deploy target counts as a declared registry without storages.
type registryHosts struct {
	registries map[string]bool
	storages   map[string]string
	targets    map[string][]primitive.Identifier
}

// validateRegistries enforces the lane's registry declarations (ADR-029
// amendment 2026-11-06). Every registry, storage and deploy target host is
// declared once and written without the default port. Every external image
// reference the controller reads in a run names, as written, the registry
// go-containerregistry dials, and that registry is a declared registry or a
// deploy target, never a storage. The anchors themselves are checked with
// every other anchor in validateTrustAnchors.
func validateRegistries(p *Lane) error {
	h, err := collectRegistryHosts(p)
	if err != nil {
		return err
	}
	return h.checkReferences(p)
}

// collectRegistryHosts gathers the deploy targets first, so a registry or
// storage that repeats a target's host is reported as such.
func collectRegistryHosts(p *Lane) (registryHosts, error) {
	h := registryHosts{
		registries: map[string]bool{},
		storages:   map[string]string{},
		targets:    map[string][]primitive.Identifier{},
	}
	for _, s := range p.Steps {
		if s.Deploy == nil {
			continue
		}
		reg, ok := s.Deploy.Method.(DeployRegistry)
		if !ok {
			continue
		}
		if err := checkDefaultPort(reg.Target.Address, 443, fmt.Sprintf("deploy step %q target", s.ID)); err != nil {
			return h, err
		}
		auth := string(reg.Target.Address.Authority())
		h.targets[auth] = append(h.targets[auth], s.ID)
	}
	for i, r := range p.Registries {
		auth, err := h.declare(r.Registry.Address, "registry", fmt.Sprintf("registries[%d].registry", i))
		if err != nil {
			return h, err
		}
		h.registries[auth] = true
		for j, st := range r.Storages {
			sAuth, sErr := h.declare(st.Address, "storage", fmt.Sprintf("registries[%d].storages[%d]", i, j))
			if sErr != nil {
				return h, sErr
			}
			h.storages[sAuth] = auth
		}
	}
	return h, nil
}

// declare admits one registry or storage authority: written without the
// default port, not yet declared as a registry or storage, and not a deploy
// target's host, which counts as declared on its own.
func (h registryHosts) declare(a endpoint.Address, kind, where string) (string, error) {
	if err := checkDefaultPort(a, 443, where); err != nil {
		return "", err
	}
	auth := string(a.Authority())
	if steps, ok := h.targets[auth]; ok {
		quoted := make([]string, len(steps))
		for i, id := range steps {
			quoted[i] = fmt.Sprintf("%q", id)
		}
		return "", fmt.Errorf("%s: %s %s already declared as target in step(s) %s", where, kind, auth, strings.Join(quoted, ", "))
	}
	if _, dup := h.storages[auth]; dup || h.registries[auth] {
		return "", fmt.Errorf("%s: %s is declared more than once", where, auth)
	}
	return auth, nil
}

// checkDefaultPort refuses an authority that spells out def, the default port
// of its protocol. Declarations and references are compared as written, so one
// host has one spelling.
func checkDefaultPort(a endpoint.Address, def primitive.Port, where string) error {
	if a.Port != nil && *a.Port == def {
		return fmt.Errorf("%s: write %s, not %s", where, a.Host, a.Authority())
	}
	return nil
}

// checkReferences holds every external image reference the controller reads
// in a run to the declarations: each step image, each pack base, each capture
// image, and the keyless trust root.
func (h registryHosts) checkReferences(p *Lane) error {
	for _, s := range p.Steps {
		if s.Image != nil {
			if err := h.checkReference(*s.Image, fmt.Sprintf("step %q image", s.ID)); err != nil {
				return err
			}
		}
		if s.Pack != nil {
			if err := h.checkReference(s.Pack.Base, fmt.Sprintf("step %q pack base", s.ID)); err != nil {
				return err
			}
		}
		if s.Deploy == nil {
			continue
		}
		for _, c := range slices.Concat(s.Deploy.Recording.PreState.Captures, s.Deploy.Recording.PostState.Captures) {
			if err := h.checkReference(c.Image, fmt.Sprintf("step %q capture %q image", s.ID, c.ID)); err != nil {
				return err
			}
		}
	}
	if p.Keyless.TrustRootRef != "" {
		return h.checkReference(p.Keyless.TrustRootRef, "keyless trustRootRef")
	}
	return nil
}

// checkReference holds one external image reference to the declarations. As
// written, its registry is present, lowercase, without the default port, and
// equal to the registry go-containerregistry dials, so no implicit rewrite
// stands between the lane text and the dial; that registry is a declared
// registry or a deploy target, never a storage.
func (h registryHosts) checkReference(ref primitive.ImageRef, where string) error {
	s := string(ref)
	parsed, err := name.ParseReference(s)
	if err != nil {
		return fmt.Errorf("%s %q: %w", where, s, err)
	}
	written, _, found := strings.Cut(s, "/")
	if !found || (!strings.ContainsAny(written, ".:") && written != "localhost") {
		return fmt.Errorf("%s %q names no registry; write the registry host in the reference", where, s)
	}
	if written != strings.ToLower(written) {
		return fmt.Errorf("%s %q: the registry host in an image reference must be lowercase", where, s)
	}
	if bare, ok := strings.CutSuffix(written, ":443"); ok {
		return fmt.Errorf("%s %q: write %s, not %s", where, s, bare, written)
	}
	if dialed := parsed.Context().RegistryStr(); dialed != written {
		return fmt.Errorf("%s %q names registry %s, but the registry dialed is %s; write %s", where, s, written, dialed, dialed)
	}
	if reg, ok := h.storages[written]; ok {
		return fmt.Errorf("%s %q names %s, a storage of registry %s; a storage is reached only by a redirect of its registry", where, s, written, reg)
	}
	if _, ok := h.targets[written]; !ok && !h.registries[written] {
		return fmt.Errorf("%s %q: registry %s is not declared in registries or as a deploy target", where, s, written)
	}
	return nil
}
