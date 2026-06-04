package executor

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdx "github.com/spdx/tools-golang/spdx/v2/v2_3"

	spdxjson "github.com/spdx/tools-golang/json"
)

// component is an internal package record produced by the native parsers.
type component struct {
	Name      string
	Version   string
	PURL      string
	Ecosystem string // "npm" or "deb"
}

// GenerateImageSBOM catalogs an extracted root filesystem and produces
// canonical CycloneDX and SPDX 2.3 JSON documents. buildTime must come
// from clock.Reproducible, never clock.Wall. The returned documents are
// deterministic: byte-identical inputs yield byte-identical outputs.
func GenerateImageSBOM(fsys fs.FS, subjectDigest string, buildTime clock.Time) (cdxDoc, spdxDoc []byte, err error) {
	components, err := walkAndCatalog(fsys)
	if err != nil {
		return nil, nil, fmt.Errorf("catalog filesystem: %w", err)
	}

	sortComponents(components)

	cdxDoc, err = renderCycloneDX(components, subjectDigest, buildTime)
	if err != nil {
		return nil, nil, fmt.Errorf("render cyclonedx: %w", err)
	}

	spdxDoc, err = renderSPDX(components, subjectDigest, buildTime)
	if err != nil {
		return nil, nil, fmt.Errorf("render spdx: %w", err)
	}

	return cdxDoc, spdxDoc, nil
}

// walkAndCatalog walks the filesystem collecting components from known
// package manifest locations.
func walkAndCatalog(fsys fs.FS) ([]component, error) {
	var components []component

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		switch {
		case strings.HasSuffix(path, "/package-lock.json") || path == "package-lock.json":
			parsed, parseErr := parseNPMLockfile(fsys, path)
			if parseErr != nil {
				return fmt.Errorf("parse %s: %w", path, parseErr)
			}
			components = append(components, parsed...)
		case path == "var/lib/dpkg/status":
			parsed, parseErr := parseDpkgStatus(fsys, path)
			if parseErr != nil {
				return fmt.Errorf("parse %s: %w", path, parseErr)
			}
			components = append(components, parsed...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return components, nil
}

// npmLockfile is the minimal structure of a package-lock.json.
type npmLockfile struct {
	Packages        map[string]npmPackageEntry `json:"packages"`
	Dependencies    map[string]npmDependencyV1 `json:"dependencies"`
	LockfileVersion int                        `json:"lockfileVersion"`
}

// npmPackageEntry is a v2/v3 lockfile entry.
type npmPackageEntry struct {
	Version string `json:"version"`
}

// npmDependencyV1 is a v1 lockfile dependency entry.
type npmDependencyV1 struct {
	Dependencies map[string]npmDependencyV1 `json:"dependencies"`
	Version      string                     `json:"version"`
}

// parseNPMLockfile parses a package-lock.json and returns components.
func parseNPMLockfile(fsys fs.FS, path string) ([]component, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, err
	}

	var lock npmLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var components []component

	switch {
	case lock.LockfileVersion >= 2 && lock.Packages != nil:
		for key, entry := range lock.Packages {
			if key == "" {
				continue // root package
			}
			name := npmPackageName(key)
			if name == "" || entry.Version == "" {
				continue
			}
			purl := npmPURL(name, entry.Version)
			components = append(components, component{
				Name:      name,
				Version:   entry.Version,
				PURL:      purl,
				Ecosystem: "npm",
			})
		}
	case lock.Dependencies != nil:
		collectNPMV1Deps(lock.Dependencies, &components)
	}

	return components, nil
}

// npmPackageName extracts the package name from a v2/v3 packages map key.
// The key is a path like "node_modules/@scope/pkg" or
// "node_modules/a/node_modules/b".
func npmPackageName(key string) string {
	idx := strings.LastIndex(key, "node_modules/")
	if idx < 0 {
		return ""
	}
	return key[idx+len("node_modules/"):]
}

// collectNPMV1Deps recursively collects components from v1 dependencies.
func collectNPMV1Deps(deps map[string]npmDependencyV1, out *[]component) {
	for name, dep := range deps {
		if dep.Version != "" {
			purl := npmPURL(name, dep.Version)
			*out = append(*out, component{
				Name:      name,
				Version:   dep.Version,
				PURL:      purl,
				Ecosystem: "npm",
			})
		}
		if dep.Dependencies != nil {
			collectNPMV1Deps(dep.Dependencies, out)
		}
	}
}

// npmPURL builds a package URL for an npm package.
func npmPURL(name, version string) string {
	p := packageurl.NewPackageURL("npm", "", name, version, nil, "")
	return p.ToString()
}

// parseDpkgStatus parses a Debian dpkg status file and returns components.
func parseDpkgStatus(fsys fs.FS, path string) ([]component, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer closer.Warn(f, "dpkg status")

	var components []component
	scanner := bufio.NewScanner(f)

	var pkgName, pkgVersion, pkgArch, pkgStatus string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Package: "):
			pkgName = strings.TrimPrefix(line, "Package: ")
		case strings.HasPrefix(line, "Version: "):
			pkgVersion = strings.TrimPrefix(line, "Version: ")
		case strings.HasPrefix(line, "Architecture: "):
			pkgArch = strings.TrimPrefix(line, "Architecture: ")
		case strings.HasPrefix(line, "Status: "):
			pkgStatus = strings.TrimPrefix(line, "Status: ")
		case line == "":
			if pkgName != "" && pkgVersion != "" && pkgStatus == "install ok installed" {
				purl := dpkgPURL(pkgName, pkgVersion, pkgArch)
				components = append(components, component{
					Name:      pkgName,
					Version:   pkgVersion,
					PURL:      purl,
					Ecosystem: "deb",
				})
			}
			pkgName, pkgVersion, pkgArch, pkgStatus = "", "", "", ""
		}
	}
	// Handle last stanza if file does not end with a blank line.
	if pkgName != "" && pkgVersion != "" && pkgStatus == "install ok installed" {
		purl := dpkgPURL(pkgName, pkgVersion, pkgArch)
		components = append(components, component{
			Name:      pkgName,
			Version:   pkgVersion,
			PURL:      purl,
			Ecosystem: "deb",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return components, nil
}

// dpkgPURL builds a package URL for a Debian package.
func dpkgPURL(name, version, arch string) string {
	var qualifiers packageurl.Qualifiers
	if arch != "" {
		qualifiers = packageurl.QualifiersFromMap(map[string]string{"arch": arch})
	}
	p := packageurl.NewPackageURL("deb", "debian", name, version, qualifiers, "")
	return p.ToString()
}

// sortComponents sorts by PURL, then name, then version for stable output.
func sortComponents(cs []component) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].PURL != cs[j].PURL {
			return cs[i].PURL < cs[j].PURL
		}
		if cs[i].Name != cs[j].Name {
			return cs[i].Name < cs[j].Name
		}
		return cs[i].Version < cs[j].Version
	})
}

// deterministicUUID produces a UUIDv5 from the subject digest for the
// CycloneDX serial number. Uses the URL namespace UUID as base.
func deterministicUUID(subjectDigest string) string {
	// UUIDv5 namespace: URL (6ba7b811-9dad-11d1-80b4-00c04fd430c8)
	nsURL := [16]byte{
		0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1,
		0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
	}
	h := sha256.New()
	h.Write(nsURL[:])
	h.Write([]byte(subjectDigest))
	sum := h.Sum(nil)

	// Truncate to 16 bytes, set version 5 and variant bits.
	var uuid [16]byte
	copy(uuid[:], sum[:16])
	uuid[6] = (uuid[6] & 0x0f) | 0x50 // version 5
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// bomRef produces a deterministic BOM-ref from a PURL.
func bomRef(purl string) string {
	h := sha256.Sum256([]byte(purl))
	return fmt.Sprintf("%x", h[:8])
}

// spdxID produces a deterministic SPDX identifier from a PURL.
// The result is safe for use as an ElementID (alphanumeric + hyphen + dot).
func spdxID(purl string) string {
	h := sha256.Sum256([]byte(purl))
	return fmt.Sprintf("Package-%x", h[:8])
}

// renderCycloneDX builds a CycloneDX 1.6 JSON document.
func renderCycloneDX(components []component, subjectDigest string, buildTime clock.Time) ([]byte, error) {
	cdxComponents := make([]cdx.Component, len(components))
	for i, c := range components {
		cdxComponents[i] = cdx.Component{
			BOMRef:     bomRef(c.PURL),
			Type:       cdx.ComponentTypeLibrary,
			Name:       c.Name,
			Version:    c.Version,
			PackageURL: c.PURL,
		}
	}

	bom := cdx.NewBOM()
	bom.SerialNumber = deterministicUUID(subjectDigest)
	bom.Metadata = &cdx.Metadata{
		Timestamp: buildTime.Format(clock.RFC3339),
		Component: &cdx.Component{
			BOMRef:  subjectDigest,
			Type:    cdx.ComponentTypeContainer,
			Name:    subjectDigest,
			Version: "",
		},
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type: cdx.ComponentTypeApplication,
				Name: "strike",
			}},
		},
	}
	bom.Components = &cdxComponents

	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(false)
	if err := enc.Encode(bom); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// renderSPDX builds an SPDX 2.3 JSON document.
func renderSPDX(components []component, subjectDigest string, buildTime clock.Time) ([]byte, error) {
	h := sha256.Sum256([]byte(subjectDigest))
	namespace := fmt.Sprintf("https://strike.dev/spdx/%x", h[:16])

	packages := make([]*spdx.Package, len(components))
	relationships := make([]*spdx.Relationship, len(components))

	for i, c := range components {
		id := common.ElementID(spdxID(c.PURL))
		packages[i] = &spdx.Package{
			PackageName:             c.Name,
			PackageSPDXIdentifier:   id,
			PackageVersion:          c.Version,
			PackageDownloadLocation: "NOASSERTION",
			FilesAnalyzed:           false,
			PackageExternalReferences: []*spdx.PackageExternalReference{{
				Category: common.CategoryPackageManager,
				RefType:  "purl",
				Locator:  c.PURL,
			}},
		}
		relationships[i] = &spdx.Relationship{
			RefA:         common.MakeDocElementID("", "DOCUMENT"),
			RefB:         common.MakeDocElementID("", string(id)),
			Relationship: common.TypeRelationshipDescribe,
		}
	}

	doc := &spdx.Document{
		SPDXVersion:       spdx.Version,
		DataLicense:       spdx.DataLicense,
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      subjectDigest,
		DocumentNamespace: namespace,
		CreationInfo: &spdx.CreationInfo{
			Created: buildTime.Format(clock.RFC3339),
			Creators: []common.Creator{
				{CreatorType: "Tool", Creator: "strike"},
			},
		},
		Packages:      packages,
		Relationships: relationships,
	}

	var buf bytes.Buffer
	if err := spdxjson.Write(doc, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
