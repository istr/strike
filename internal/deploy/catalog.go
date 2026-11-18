package deploy

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"sort"
	"strings"

	"github.com/istr/strike/internal/clock"
	"github.com/istr/strike/internal/closer"
	"github.com/istr/strike/internal/primitive"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
)

// component is an internal package record produced by the native parsers.
type component struct {
	Name      string
	Version   string
	PURL      string
	Ecosystem string // "npm", "deb", or "golang"
}

// GenerateImageSBOM catalogs an extracted root filesystem and produces a
// CycloneDX document in the canonical form of ADR-059 D2. buildTime must come
// from clock.Reproducible, never clock.Wall. The returned document is
// deterministic: byte-identical inputs yield a byte-identical output.
func GenerateImageSBOM(fsys fs.FS, subjectDigest primitive.Digest, buildTime clock.Time) ([]byte, error) {
	components, err := walkAndCatalog(fsys)
	if err != nil {
		return nil, fmt.Errorf("catalog filesystem: %w", err)
	}

	if len(components) == 0 {
		log.Printf("INFO   sbom: no components cataloged for %s", subjectDigest)
	}

	sortComponents(components)

	doc, err := renderCycloneDX(components, subjectDigest, buildTime)
	if err != nil {
		return nil, fmt.Errorf("render cyclonedx: %w", err)
	}
	return doc, nil
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
		default:
			parsed := catalogGoBinary(fsys, path, d)
			components = append(components, parsed...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return components, nil
}

// catalogGoBinary attempts to read Go build info from an executable file.
// Returns nil if the file is not a regular executable or not a Go binary.
func catalogGoBinary(fsys fs.FS, path string, d fs.DirEntry) []component {
	if !d.Type().IsRegular() {
		return nil
	}
	info, err := d.Info()
	if err != nil {
		return nil
	}
	if info.Mode()&0o111 == 0 {
		return nil
	}
	parsed, err := parseGoBuildinfo(fsys, path)
	if err != nil {
		return nil // not a Go binary -- skip silently
	}
	return parsed
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

// parseGoBuildinfo attempts to read Go build info from an executable file
// and returns its module dependencies as components. Returns an error if
// the file is not a Go binary (callers skip silently).
func parseGoBuildinfo(fsys fs.FS, path string) ([]component, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer closer.Warn(f, "go-buildinfo")

	var info *buildinfo.BuildInfo
	if ra, ok := f.(io.ReaderAt); ok {
		info, err = buildinfo.Read(ra)
	} else {
		var data []byte
		data, err = io.ReadAll(f)
		if err != nil {
			return nil, err
		}
		info, err = buildinfo.Read(bytes.NewReader(data))
	}
	if err != nil {
		return nil, err
	}

	var components []component
	if info.Main.Path != "" && info.Main.Version != "" {
		purl := golangPURL(info.Main.Path, info.Main.Version)
		components = append(components, component{
			Name:      info.Main.Path,
			Version:   info.Main.Version,
			PURL:      purl,
			Ecosystem: "golang",
		})
	}
	for _, dep := range info.Deps {
		if dep.Path == "" || dep.Version == "" {
			continue
		}
		purl := golangPURL(dep.Path, dep.Version)
		components = append(components, component{
			Name:      dep.Path,
			Version:   dep.Version,
			PURL:      purl,
			Ecosystem: "golang",
		})
	}
	return components, nil
}

// golangPURL builds a package URL for a Go module.
func golangPURL(path, version string) string {
	p := packageurl.NewPackageURL("golang", "", path, version, nil, "")
	return p.ToString()
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

// contentUUID derives the serial number of a CycloneDX document from the
// document it names (ADR-059 D7): a name-based UUIDv8 as in RFC 9562 Appendix
// B.2, the first 128 bits of SHA-256 over the URL namespace ID followed by doc,
// the canonical document without its serial number, with the version and
// variant bits set. Identical documents share a serial number.
func contentUUID(doc []byte) string {
	// RFC 9562 namespace ID for URLs: 6ba7b811-9dad-11d1-80b4-00c04fd430c8
	nsURL := [16]byte{
		0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1,
		0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
	}
	h := sha256.New()
	h.Write(nsURL[:])
	h.Write(doc)
	sum := h.Sum(nil)

	// Truncate to 16 bytes, set version 8 and variant bits.
	var uuid [16]byte
	copy(uuid[:], sum[:16])
	uuid[6] = (uuid[6] & 0x0f) | 0x80 // version 8
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// bomRef produces a deterministic BOM-ref from a PURL.
func bomRef(purl string) string {
	h := sha256.Sum256([]byte(purl))
	return fmt.Sprintf("%x", h[:8])
}

// renderCycloneDX builds a CycloneDX 1.7 JSON document in the canonical form
// of ADR-059 D2. Its tool entry names strike and the version of strike
// (ADR-060 D7). The document is rendered once without a serial number, and
// the serial number derived from those bytes is set before the final
// rendering (ADR-059 D7).
func renderCycloneDX(components []component, subjectDigest primitive.Digest, buildTime clock.Time) ([]byte, error) {
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
	bom.SpecVersion = cdx.SpecVersion1_7
	bom.Metadata = &cdx.Metadata{
		Timestamp: buildTime.Format(clock.RFC3339),
		Component: &cdx.Component{
			BOMRef:  subjectDigest.String(),
			Type:    cdx.ComponentTypeContainer,
			Name:    subjectDigest.String(),
			Version: "",
		},
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    "strike",
				Version: string(strikeVersion),
			}},
		},
	}
	bom.Components = &cdxComponents

	unnamed, err := encodeCanonical(bom)
	if err != nil {
		return nil, err
	}
	bom.SerialNumber = contentUUID(unnamed)
	return encodeCanonical(bom)
}

// encodeCanonical marshals bom with the CycloneDX library and re-serializes
// the result in canonical form (ADR-059 D2).
func encodeCanonical(bom *cdx.BOM) ([]byte, error) {
	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).Encode(bom); err != nil {
		return nil, err
	}
	return canonicalize(buf.Bytes())
}
