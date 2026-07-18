// Source provenance records produced by source-fetch container steps. Strike
// validates these after step exit and includes them in the deploy attestation
// envelope. A concept-tier value family.
package provenance

import "github.com/istr/strike/contract/primitive"

#Record: (#Git |
	#Tarball |
	#OCI |
	#URL) @go(-)

// #SourceType is the provenance source discriminator vocabulary.
#SourceType: "git" | "tarball" | "oci" | "url"

#Git: {
	@go(Git)
	type:       "git"                @go(Type,type=SourceType)
	uri:        string               @go(URI)
	commit:     primitive.#GitCommit @go(Commit)
	ref?:       string               @go(Ref)
	fetchedAt?: primitive.#Timestamp @go(FetchedAt)
}

#Tarball: {
	@go(Tarball)
	type:       "tarball"            @go(Type,type=SourceType)
	uri:        string               @go(URI)
	sha256:     primitive.#Sha256    @go(SHA256)
	fetchedAt?: primitive.#Timestamp @go(FetchedAt)
}

#OCI: {
	@go(OCI)
	type:       "oci"                @go(Type,type=SourceType)
	uri:        string               @go(URI)
	digest:     primitive.#Digest    @go(Digest)
	fetchedAt?: primitive.#Timestamp @go(FetchedAt)
}

#URL: {
	@go(URL)
	type:       "url"                @go(Type,type=SourceType)
	uri:        string               @go(URI)
	sha256:     primitive.#Sha256    @go(SHA256)
	fetchedAt?: primitive.#Timestamp @go(FetchedAt)
}
