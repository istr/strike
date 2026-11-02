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

// #OCIName is an OCI distribution-spec repository <name>: slash-separated
// lowercase path components with dot, underscore, and dash separators
// (github.com/opencontainers/distribution-spec, the <name> grammar). It
// carries no registry authority, no tag, and no digest by construction: the
// push destination pairs it with a declared endpoint, and the pushed digest
// is the result of the push, bound in the attestation (ADR-051 D6).
#OCIName: =~"^[a-z0-9]+((\\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\\.|_|__|-+)[a-z0-9]+)*)*$"

// #Base64 is standard padded base64 (the proto3-JSON form of a bytes field and
// the SSH public-key body wire form).
#Base64: =~"^[A-Za-z0-9+/]+={0,2}$"

// _sha256Hex is the shared 64-hex sha256 body, single-sourced and composed by
// interpolation into the anchored hash patterns (ADR-047).
_sha256Hex: "[a-f0-9]{64}"

// #GitCommit is a git object name: 40-hex SHA-1 or 64-hex SHA-256.
#GitCommit: =~"^[a-f0-9]{40}$|^\(_sha256Hex)$"

// #GitRef is a git reference name under the rules of git check-ref-format:
// no ASCII control character, space, '~', '^', ':', '?', '*', '[' or '\',
// no "..", no "@{", no component that begins with '.' or ends with
// ".lock", no leading, trailing or doubled '/', no trailing '.', and not
// the single character '@'. A "refs/" prefix is not required: a CI provider
// that passes a raw claim may carry a short name.
#GitRef: =~"^[^\\x00-\\x20\\x7f~^:?*\\[\\\\]+$" &
	!~"\\.\\." &
	!~"@\\{" &
	!~"^/" &
	!~"/$" &
	!~"//" &
	!~"(^|/)\\." &
	!~"\\.lock(/|$)" &
	!~"\\.$" &
	!="@"

// #Sha256 is a bare lowercase 64-hex sha256 digest (no algorithm prefix).
// For the prefixed "sha256:<hex>" form use #Digest.
#Sha256: =~"^\(_sha256Hex)$"

#ImageRef: =~"^.+@sha256:\(_sha256Hex)$"

#FileArtifactType: "file" | "directory"

// #Digest is the wire form of a content-addressed digest: the prefixed
// "sha256:<64-hex>" string that crosses strike's serialization boundary. It is
// the canonical digest type; strike carries digests as this value directly.
#Digest: =~"^sha256:\(_sha256Hex)$"

#Duration: =~"^[0-9]+(s|m|h)$"

// #Timestamp is an RFC3339 wall-clock timestamp string. The regex is
// intentionally loose and not a full RFC3339 grammar.
#Timestamp: =~"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"

// #Host is a bare network hostname or IP literal, lowercase ASCII, without a
// port. Punycode is required for internationalized domains.
#Host: =~"^[a-z0-9.-]+$"

// #IP is a bare IP literal, v4 or v6, carrying no port and no zone id. The
// alphabet is the whole schema constraint: a complete IPv6 grammar is
// impractically large as a regex, so the pattern narrows the character set to
// lowercase hex, dots, and colons, and IP.Addr is the binding check. The
// split is ADR-027's CUE-first bullet as ADR-039's amendment reads it -- the
// regex is the canonical shape, Go adds what the regex cannot express. A few
// hostnames pass the alphabet by coincidence; Go rejects them.
#IP: =~"^[0-9a-f.:]+$"

// #Port is a TCP/UDP port number, 1-65535.
#Port: int & >=1 & <=65535

// #UserSpec is the OCI image-config user: a uid, uid:gid, user, or user:group
// string. Left unconstrained because all of these forms are valid; it is a
// named type so the field is carried as primitive.UserSpec end to end.
#UserSpec: string

// #StringOrURI is the RFC 7519 (section 2) StringOrURI: an arbitrary string,
// except that a value containing ':' must be a URI (RFC 3986); values are
// compared case-sensitively and verbatim. It types a signer identity, the SAN
// a Fulcio certificate carries: an email address (colon-free) or a URI of any
// scheme. The colon-implies-URI rule and non-emptiness are not encoded here;
// StringOrURI.Validate enforces them after parse.
#StringOrURI: string

// #URIReference is an RFC 3986 URI-reference, absolute or relative: the form
// a Fulcio source-repository or build-config extension carries, which SHOULD
// be a fully qualified URL but may omit the scheme. Non-emptiness, the
// absence of whitespace and control characters, and parseability are not
// encoded here; URIReference.Validate enforces them after parse.
#URIReference: string

// #RunnerEnvironment is a Fulcio runner-environment value: lowercase
// alphanumeric words joined by '-', such as "github-hosted" or
// "self-hosted".
#RunnerEnvironment: =~"^[a-z0-9]+(-[a-z0-9]+)*$"
