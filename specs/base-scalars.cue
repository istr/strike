// Base scalar types -- shared, composable leaf constraints (ADR-047).

package lane

// Path is the shared canonicalization base: no double slashes, no "." or
// ".." segments, no trailing slash. Not used directly on fields; use
// AbsPath or RelPath.
#Path: string &
	!~"//" &
	!~"^\\.\\.($|/)" &
	!~"/\\.\\.($|/)" &
	!~"^\\.($|/)" &
	!~"/\\.($|/)" &
	!~".+/$"

// AbsPath is a canonical absolute path (starts with "/").
#AbsPath: #Path & =~"^/"

// RelPath is a canonical relative path (no leading "/").
#RelPath: #Path & =~"^[^/]"

// #Identifier is a stable, cross-referenceable entity id. The grammar is the
// RFC 1123 DNS label (lowercase alphanumeric and '-', start and end
// alphanumeric, at most 63 chars) so an id is usable verbatim as a Kubernetes
// resource name, an OCI tag component, and a DNS label.
#Identifier: =~"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$"

#ImageRef: =~"^.+@sha256:[a-f0-9]{64}$"

#ArtifactType: "file" | "directory" | "image"

#FileArtifactType: "file" | "directory"

#Digest: =~"^sha256:[a-f0-9]{64}$" @go(-)

#Duration: =~"^[0-9]+(s|m|h)$"
