// strike lane schema — target design
//
// Three step types, one supply chain:
//   run:    execute a command in a container, produce typed artifacts
//   pack:   assemble an OCI image from artifacts (no container, no RUN)
//   deploy: apply artifacts to a target, produce state attestation

package lane

@go(lane) // generated go package name

// ---------------------------------------------------------------------------
// Top-level lane
// ---------------------------------------------------------------------------

#Lane: {
	@go(Lane)
	name:     string @go(Name)
	registry: string & =~"^[a-z0-9./-]+" @go(Registry)
	secrets: [Name=string]: #SecretSource @go(Secrets)
	steps: [#Step, ...#Step] @go(Steps)
	defaults?: #LaneDefaults @go(Defaults,optional=nillable)
}

#LaneDefaults: {
	@go(LaneDefaults)
	timeout: *"10m" | #Duration @go(Timeout)
}

// ---------------------------------------------------------------------------
// Shared path type — absolute and canonical container path
// ---------------------------------------------------------------------------

// ContainerPath is an absolute, canonical path inside a container.
// Rejects: relative paths, double slashes, dot segments, trailing slashes.
#ContainerPath: string & =~"^/" & !~"//" & !~"/\\.(/|$)" & !~"/\\.\\.(/|$)" & !~".+/$"

// ---------------------------------------------------------------------------
// Step — the union type
// ---------------------------------------------------------------------------

#Step: {
	@go(Step)
	name:        string @go(Name)
	image?:      (#ImageRef | #LocalImageRef) @go(Image)
	image_from?: #ImageFrom @go(ImageFrom,optional=nillable)
	args:        [...string] @go(Args)
	env:         [string]: string @go(Env)
	inputs:      [...#InputRef] @go(Inputs)
	outputs:     [...#OutputSpec] @go(Outputs)
	secrets:     [...#SecretRef] @go(Secrets)
	workdir?:    #ContainerPath @go(Workdir)
	peers?:      [...#Peer] @go(Peers)
	timeout?:    #Duration @go(Timeout)
	pack?:       #PackSpec @go(Pack,optional=nillable)
	deploy?:     #DeploySpec @go(Deploy,optional=nillable)
	provenance?: #ProvenanceSpec @go(Provenance,optional=nillable)
	// constraint: exactly one of image, image_from, pack, or deploy -- validated in Go
}

// ---------------------------------------------------------------------------
// Image references
// ---------------------------------------------------------------------------

#ImageRef: =~"^.+@sha256:[a-f0-9]{64}$"

#LocalImageRef: =~"^[a-z0-9][a-z0-9./_-]*(:[a-zA-Z0-9._-]+)?$"

#ImageFrom: {
	@go(ImageFrom)
	step:   string @go(Step)
	output: string @go(Output)
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

#InputRef: {
	@go(InputRef)
	name:    string @go(Name)
	from:    string @go(From)           // "step_name.output_name"
	mount:   #ContainerPath @go(Mount)
	digest?: #Digest @go(Digest,type=*Digest)
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#ArtifactType: "file" | "directory" | "image"

#OutputSpec: {
	@go(OutputSpec)
	name:      string @go(Name)
	type:      #ArtifactType @go(Type)
	path:      #ContainerPath @go(Path)
	expected?: #OutputValidation @go(Expected,optional=nillable)
}

#OutputValidation: {
	@go(OutputValidation)
	content_type?: string @go(ContentType)
	min_size?:     int @go(MinSize)
	max_size?:     int @go(MaxSize)
}

// ---------------------------------------------------------------------------
// Network peers -- declared trust contracts (ADR-005, ADR-007)
// ---------------------------------------------------------------------------

// Peer is a discriminated union over the supported network protocols.
// A non-empty peers list opts the step into network access; absent or
// empty means --network=none. Peers flow into the deploy attestation.
#Peer: #HTTPSPeer | #SSHPeer | #OCIPeer

// HTTPSPeer declares an HTTPS endpoint together with its server-trust anchor.
#HTTPSPeer: {
	@go(HTTPSPeer)
	type: "https" @go(Type)
	// host is hostname or IPv4 literal, optionally with :port.
	// Lowercase ASCII; punycode required for internationalized domains.
	host:  string & =~"^[a-z0-9.-]+(:[0-9]+)?$" @go(Host)
	trust: #HTTPSTrust @go(Trust)
}

// HTTPSTrust selects between certificate-fingerprint pinning and CA-bundle
// validation. The system trust store is not an option (deferred per ADR-021).
#HTTPSTrust: #FingerprintTrust | #CABundleTrust

#FingerprintTrust: {
	@go(FingerprintTrust)
	mode:        "cert_fingerprint" @go(Mode)
	fingerprint: =~"^sha256:[a-f0-9]{64}$" @go(Fingerprint)
}

#CABundleTrust: {
	@go(CABundleTrust)
	mode: "ca_bundle" @go(Mode)
	// path is a container-internal path. The executor mounts the lane-
	// relative bundle file there in Phase 2; in Phase 1 the field is
	// declaratory only.
	path: #ContainerPath @go(Path)
}

// SSHPeer declares an SSH endpoint with explicit known_hosts entries.
// Phase 1 is declaratory: ssh-agent socket forwarding and known_hosts
// file mounting remain the lane author's responsibility via secrets and
// inputs.
#SSHPeer: {
	@go(SSHPeer)
	type:        "ssh" @go(Type)
	host:        string & =~"^[a-z0-9.-]+(:[0-9]+)?$" @go(Host)
	known_hosts: [...#KnownHostEntry] @go(KnownHosts)
}

// KnownHostEntry is one server key, an OpenSSH known_hosts line
// decomposed into typed fields.
#KnownHostEntry: {
	@go(KnownHostEntry)
	key_type: "ssh-ed25519" | "ecdsa-sha2-nistp256" |
		"rsa-sha2-512" | "rsa-sha2-256" @go(KeyType)
	// key is the base64-encoded public key body (no PEM armor).
	key: =~"^[A-Za-z0-9+/]+={0,2}$" @go(Key)
}

// OCIPeer declares an OCI registry. Content trust is enforced via image
// digest pinning (#ImageRef); the optional trust field covers the
// registry's TLS connection.
#OCIPeer: {
	@go(OCIPeer)
	type:     "oci" @go(Type)
	registry: string & =~"^[a-z0-9.-]+(:[0-9]+)?$" @go(Registry)
	trust?:   #HTTPSTrust @go(Trust,optional=nillable)
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

#SecretSource: =~"^(env|file|op)://.+"

#SecretRef: {
	@go(SecretRef)
	name: string @go(Name)
	env:  string @go(Env)
}

// ---------------------------------------------------------------------------
// Pack — deterministic OCI image assembly
// ---------------------------------------------------------------------------

#PackSpec: {
	@go(PackSpec)
	base:          #ImageRef @go(Base)
	files:         [...#PackFile] @go(Files)
	packages?:     [...#Package] @go(Packages)
	config_files?: [Path=string]: #FileEntry @go(ConfigFiles)
	config?:       #ImageConfig @go(Config,optional=nillable)
	annotations?:  [string]: string @go(Annotations)
	sbom?:         #SBOMConfig @go(SBOM,optional=nillable)
	sign?:         #SignConfig @go(Sign,optional=nillable)
	push?:         [...string] @go(Push)
}

#PackFile: {
	@go(PackFile)
	from: string @go(From)
	dest: #ContainerPath @go(Dest)
	mode: *0o755 | int @go(Mode)
	uid?: int @go(UID)
	gid?: int @go(GID)
}

#Package: {
	@go(Package)
	name:     string @go(Name)
	version?: string @go(Version)
}

#FileEntry: {
	@go(FileEntry)
	content: string @go(Content)
	mode:    *0o644 | int @go(Mode)
	uid:     *0 | int @go(UID)
	gid:     *0 | int @go(GID)
}

#ImageConfig: {
	@go(ImageConfig)
	env?:        [string]: string @go(Env)
	entrypoint?: [...string] @go(Entrypoint)
	cmd?:        [...string] @go(Cmd)
	workdir?:    string @go(Workdir)
	user?:       string @go(User)
	labels?:     [string]: string @go(Labels)
}

// ---------------------------------------------------------------------------
// Deploy — apply to target, mandatory state attestation
// ---------------------------------------------------------------------------

#DeploySpec: {
	@go(DeploySpec)
	method:      #DeployMethod @go(Method)
	artifacts:   [Name=string]: #ArtifactRef @go(Artifacts)
	target:      #DeployTarget @go(Target)
	attestation: #AttestationSpec @go(Attestation)
	source?: {
		git_image: #ImageRef
	} @go(Source,optional=nillable)
}

#DeployMethod: (#DeployKubernetes | #DeployRegistry | #DeployCustom) @go(-)

#DeployKubernetes: {
	@go(DeployKubernetes)
	type:        "kubernetes" @go(Type)
	image:       #ImageRef @go(Image)
	namespace:   string @go(Namespace)
	strategy:    *"apply" | "replace" | "rollout" @go(Strategy)
	kubeconfig?: string @go(Kubeconfig)
}

#DeployRegistry: {
	@go(DeployRegistry)
	type:   "registry" @go(Type)
	source: string @go(Source)
	target: string @go(Target)
}

#DeployCustom: {
	@go(DeployCustom)
	type:        "custom" @go(Type)
	image:       #ImageRef @go(Image)
	args:        [...string] @go(Args)
	env:         [string]: string @go(Env)
	entrypoint?: [...string] @go(Entrypoint)
}

#ArtifactRef: {
	@go(ArtifactRef)
	from: string @go(From)
}

#DeployTarget: {
	@go(DeployTarget)
	type:        string @go(Type)
	description: string @go(Description)
	url?:        string @go(URL)
	namespace?:  string @go(Namespace)
}

// ---------------------------------------------------------------------------
// State capture
// ---------------------------------------------------------------------------

#AttestationSpec: {
	@go(AttestationSpec)
	pre_state:  #StateCaptureSpec @go(PreState)
	post_state: #StateCaptureSpec @go(PostState)
	drift:      #DriftSpec @go(Drift)
}

#StateCaptureSpec: {
	@go(StateCaptureSpec)
	required: *true | bool @go(Required)
	capture:  [...#StateCapture] @go(Capture)
}

#DriftSpec: {
	@go(DriftSpec)
	detect:   *true | bool @go(Detect)
	on_drift: *"warn" | "fail" | "record" @go(OnDrift)
}

#StateCapture: {
	@go(StateCapture)
	name:     string @go(Name)
	image:    #ImageRef @go(Image)
	command:  [...string] @go(Command)
	peers?:   [...#Peer] @go(Peers)
	mounts?:  [...#CaptureMount] @go(Mounts)
}

#CaptureMount: {
	@go(CaptureMount)
	source: string @go(Source)
	target: #ContainerPath @go(Target)
}

// ---------------------------------------------------------------------------
// Provenance declaration
// ---------------------------------------------------------------------------

// ProvenanceSpec declares that a step produces a source-provenance
// record at a specific path inside its container, in a specific format.
// After step exit, strike reads the file, validates against the schema
// for the declared type, and stores the resulting record in lane state.
//
// path is an absolute container path that must lie within an output mount.
// require_signed enforces that the produced record's signature.verified
// is true; otherwise the step fails. Strike trusts the container's claim
// -- cryptographic verification happens inside the container, not in strike.
#ProvenanceSpec: {
	@go(ProvenanceSpec)
	type:            "git" | "tarball" | "oci" | "url" @go(Type)
	path:            #ContainerPath @go(Path)
	require_signed?: bool @go(RequireSigned)
}

// ---------------------------------------------------------------------------
// Supply chain types
// ---------------------------------------------------------------------------

#SBOMConfig: {
	@go(SBOMConfig)
	generate: *true | bool @go(Generate)
	format:   *"spdx-json" | "cyclonedx-json" @go(Format)
}

#SignConfig: {
	@go(SignConfig)
	enabled: *true | bool @go(Enabled)
	keyless: *true | bool @go(Keyless)
	key?:    string @go(Key)
}

#Digest: =~"^sha256:[a-f0-9]{64}$" @go(-)
#Duration: =~"^[0-9]+(s|m|h)$"

// ---------------------------------------------------------------------------
// Runtime artifact carrier
// ---------------------------------------------------------------------------

// Artifact is a content-addressed output from a step. This type flows
// between executor, lane state, and deploy -- it is the internal
// interface for artifact handover between pipeline phases.
#Artifact: {
	@go(Artifact)
	type:          #ArtifactType @go(Type)
	digest:        #Digest @go(Digest,type=Digest)
	local_path?:   string @go(LocalPath)
	size:          int & >=0 @go(Size)
	content_type?: string @go(ContentType)
	metadata?:     [string]: string @go(Metadata)
	rekor?:        #RekorEntry @go(Rekor,optional=nillable)
}

// ---------------------------------------------------------------------------
// Rekor transparency log types
// ---------------------------------------------------------------------------

// RekorEntry holds the transparency log response from a Rekor
// hashedrekord submission. When present, all subfields are required --
// a partial Rekor entry is invalid. Used by both #Artifact (internal
// carrier) and deploy.#SignedArtifact (attestation output).
#RekorEntry: {
	@go(RekorEntry)

	// uuid is the entry identifier in the transparency log.
	// Needed for lookups via GET /api/v1/log/entries/{uuid}.
	uuid: =~"^[0-9a-f]{64,}$" @go(UUID)

	// log_index is the global sequence number in the transparency log.
	log_index: int & >=0 @go(LogIndex)

	// log_id is the hex-encoded hash of the log's public key.
	log_id: =~"^[a-f0-9]{64}$" @go(LogID)

	// integrated_time is the Unix timestamp when the entry was added.
	integrated_time: int & >0 @go(IntegratedTime)

	// body is the base64-encoded entry body.
	body: string @go(Body)

	// signed_entry_timestamp is the base64-encoded SET proving
	// the log server processed this entry. Verifiers use this to
	// re-verify the SET offline without contacting Rekor.
	signed_entry_timestamp: string @go(SignedEntryTimestamp)

	// inclusion_proof holds the Merkle tree proof for this entry.
	inclusion_proof: #InclusionProof @go(InclusionProof)
}

// InclusionProof holds the Merkle tree proof for a Rekor entry.
#InclusionProof: {
	@go(InclusionProof)

	// log_index is the leaf index in the Merkle tree.
	log_index: int & >=0 @go(LogIndex)

	// root_hash is the hex-encoded tree root at inclusion time.
	root_hash: =~"^[a-f0-9]{64}$" @go(RootHash)

	// tree_size is the number of leaves when the proof was generated.
	tree_size: int & >=1 @go(TreeSize)

	// hashes are the hex-encoded sibling hashes from leaf to root.
	hashes: [...=~"^[a-f0-9]{64}$"] @go(Hashes)
}
