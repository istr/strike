// Source provenance records produced by source-fetch container steps.
// Strike validates these after step exit and includes them in the
// deploy attestation envelope.
//
// Strike does not know how a container fetches its source. Strike does
// know what a conformant provenance record looks like for each of the
// supported source types.

package lane

// ---------------------------------------------------------------------------
// Discriminated union of provenance record types
// ---------------------------------------------------------------------------

#ProvenanceRecord: (#GitProvenanceRecord |
	#TarballProvenanceRecord |
	#OCIProvenanceRecord |
	#URLProvenanceRecord) @go(-)

// ---------------------------------------------------------------------------
// Git
// ---------------------------------------------------------------------------

#GitProvenanceRecord: {
	@go(GitProvenanceRecord)
	type:       "git"                                      @go(Type)
	uri:        string                                     @go(URI)
	commit:     string & =~"^[a-f0-9]{40}$|^[a-f0-9]{64}$" @go(Commit)
	ref?:       string                                     @go(Ref)
	fetchedAt?: string                                     @go(FetchedAt)
}

// ---------------------------------------------------------------------------
// Tarball / archive download
// ---------------------------------------------------------------------------

#TarballProvenanceRecord: {
	@go(TarballProvenanceRecord)
	type:       "tarball"                   @go(Type)
	uri:        string                      @go(URI)
	sha256:     string & =~"^[a-f0-9]{64}$" @go(SHA256)
	fetchedAt?: string                      @go(FetchedAt)
}

// ---------------------------------------------------------------------------
// OCI image / artifact pull
// ---------------------------------------------------------------------------

#OCIProvenanceRecord: {
	@go(OCIProvenanceRecord)
	type:       "oci"                              @go(Type)
	uri:        string                             @go(URI)
	digest:     string & =~"^sha256:[a-f0-9]{64}$" @go(Digest)
	fetchedAt?: string                             @go(FetchedAt)
}

// ---------------------------------------------------------------------------
// Generic URL fetch (no integrity guarantee beyond what the container claims)
// ---------------------------------------------------------------------------

#URLProvenanceRecord: {
	@go(URLProvenanceRecord)
	type:       "url"                       @go(Type)
	uri:        string                      @go(URI)
	sha256:     string & =~"^[a-f0-9]{64}$" @go(SHA256)
	fetchedAt?: string                      @go(FetchedAt)
}
