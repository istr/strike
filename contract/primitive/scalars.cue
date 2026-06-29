// Base scalar types -- shared, composable leaf constraints (ADR-047).

package primitive

// Path is the shared canonicalization base: no double slashes, no "." or
// ".." segments, no trailing slash. Not used directly on fields; use
// AbsPath or RelPath. Abstract CUE base with no named Go type; the
// AbsPath/RelPath subtypes carry the Go types.
#Path: !~"//" &
	!~"^\\.\\.($|/)" &
	!~"/\\.\\.($|/)" &
	!~"^\\.($|/)" &
	!~"/\\.($|/)" &
	!~".+/$" @go(-)

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
// the SSH public-key body wire form).
#Base64: =~"^[A-Za-z0-9+/]+={0,2}$"

// _sha256Hex is the shared 64-hex sha256 body, single-sourced and composed by
// interpolation into the anchored hash patterns (ADR-047).
_sha256Hex: "[a-f0-9]{64}"

// #GitCommit is a git object name: 40-hex SHA-1 or 64-hex SHA-256.
#GitCommit: =~"^[a-f0-9]{40}$|^\(_sha256Hex)$"

// #Sha256 is a bare lowercase 64-hex sha256 digest (no algorithm prefix).
// For the prefixed "sha256:<hex>" form use #Digest.
#Sha256: =~"^\(_sha256Hex)$"

#ImageRef: =~"^.+@sha256:\(_sha256Hex)$"

#ArtifactType: "file" | "directory" | "image"

#FileArtifactType: "file" | "directory"

// #Digest is the wire form of a content-addressed digest: the prefixed
// "sha256:<64-hex>" string that crosses strike's serialization boundary. It is
// the canonical digest type; strike carries digests as this value directly.
#Digest: =~"^sha256:\(_sha256Hex)$"

#Duration: =~"^[0-9]+(s|m|h)$"

// #Host is a bare network hostname or IP literal, lowercase ASCII, without a
// port. Punycode is required for internationalized domains.
#Host: =~"^[a-z0-9.-]+$"

// #Port is a TCP/UDP port number, 1-65535.
#Port: int & >=1 & <=65535

// #UserSpec is the OCI image-config user: a uid, uid:gid, user, or user:group
// string. Left unconstrained because all of these forms are valid; it is a
// named type so the field is carried as primitive.UserSpec end to end.
#UserSpec: string
