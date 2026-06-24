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

// #Base64 is standard padded base64 (the proto3-JSON form of a bytes field and
// the SSH public-key body wire form). @go(-): used inline, no named Go type.
#Base64: =~"^[A-Za-z0-9+/]+={0,2}$" @go(-)

// #GitCommit is a git object name: 40-hex SHA-1 or 64-hex SHA-256.
// @go(-): used inline, no named Go type.
#GitCommit: =~"^[a-f0-9]{40}$|^[a-f0-9]{64}$" @go(-)

#ImageRef: =~"^.+@sha256:[a-f0-9]{64}$"

#ArtifactType: "file" | "directory" | "image"

#FileArtifactType: "file" | "directory"

#Digest: =~"^sha256:[a-f0-9]{64}$" @go(-)

#Duration: =~"^[0-9]+(s|m|h)$"
