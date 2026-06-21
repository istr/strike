// strike lane schema -- target design
//
// Three step types, one supply chain:
//   run:    execute a command in a container, produce typed artifacts
//   pack:   assemble an OCI image from artifacts (no container, no RUN)
//   deploy: apply artifacts to a target, produce state recording

package lane

@go(lane) // generated go package name

// ---------------------------------------------------------------------------
// Top-level lane
// ---------------------------------------------------------------------------

#Lane: {
	@go(Lane)
	name: string @go(Name)
	// Stable identifier assigned at authoring time. Used by external
	// verifiers to pair attestations against the same lane across runs.
	// Distinct from `name`, which is human-display.
	id:       #Identifier                                                             @go(ID,type=string)
	registry: string & =~"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]+)?(/[a-z0-9._-]+)*$" @go(Registry)
	// NOTE: the exported JSON Schema for this map is open (patternProperties
	// only), unlike artifacts (additionalProperties:false). strike validates
	// CUE-natively in parse.go and rejects non-#Identifier keys in-process; an
	// external verifier consuming only the exported schema would not. Accepted
	// until the secrets contract is revisited separately (YAGNI).
	secrets: {
		[ID=#Identifier]: #SecretSource
	} @go(Secrets,type=map[string]SecretSource)
	steps: [#Step, ...#Step] @go(Steps)
	resolver: #DNSResolver @go(Resolver,type="github.com/istr/strike/internal/transport".DNSResolver)
	oidc:     #OIDCConfig  @go(OIDC)
	// Keyless signing+verification config (ADR-040 3b, ADR-041). `endpoints`
	// is required: every deploy attestation is produced through Fulcio, Rekor
	// v2, and the TSA, fail-closed. `trustRoot` (inline replica) XOR
	// `trustRootRef` (OCI digest) supplies the verification anchor; at most
	// one, and -- forward-constraint for verify -- absence here means the
	// anchor MUST come from --trust-root-ref, with NO implicit default.
	keyless: #Keyless @go(Keyless)
	baseSbomSigners?: [...#SBOMSigner] @go(BaseSBOMSigners,optional=nillable)
	defaults?: #LaneDefaults @go(Defaults,optional=nillable)
}

#LaneDefaults: {
	@go(LaneDefaults)
	timeout: *"10m" | #Duration @go(Timeout)
}

// OIDCConfig declares the lane-wide keyless signing identity (ADR-040 D5).
// Required: a lane that cannot be attested with a verifiable signature is
// not a valid strike lane (mirrors ADR-039 D1 for the signing layer). The
// IdP is a declared peer; trust pins its endpoints with the same #TLSTrust
// anchor resolver.trust and #HTTPSPeer.trust use. validate/dag check
// declaration only and never contact the IdP; the live keyless flow runs at
// the sign step of run.
#OIDCConfig: {
	@go(OIDCConfig)

	issuer:   string    @go(Issuer)   // iss / issuer-url; config only, no IdP contact at validate/dag
	audience: string    @go(Audience) // aud
	identity: string    @go(Identity) // expected SAN subject Fulcio writes into the cert
	trust:    #TLSTrust @go(Trust,type="github.com/istr/strike/internal/transport".TLSTrust)
}

// KeylessEndpoints declares the sigstore services the keyless chain dials
// (ADR-040 D2/3b): Fulcio (CA), Rekor v2 (transparency log), and an RFC3161
// TSA (Rekor v2 has no integrated timestamp; trusted time is the RFC3161
// token). Every endpoint is HTTPS-only with a mandatory declared trust
// anchor (#HTTPSEndpoint). URLs are bases; the clients append the fixed
// well-known API paths.
#KeylessEndpoints: {
	@go(KeylessEndpoints)

	fulcio: #HTTPSEndpoint @go(Fulcio,type="github.com/istr/strike/internal/transport".HTTPSEndpoint)
	rekor:  #HTTPSEndpoint @go(Rekor,type="github.com/istr/strike/internal/transport".HTTPSEndpoint)
	tsa:    #HTTPSEndpoint @go(TSA,type="github.com/istr/strike/internal/transport".HTTPSEndpoint)
}

// Keyless wraps the endpoint set with at most one trust-root source.
// trustRoot and trustRootRef are mutually exclusive and both optional (anchor
// then supplied at verify, no implicit default). gengotypes collapses a CUE
// disjunction to its base struct, so the mutual exclusion is enforced below
// CUE, in unmarshalKeyless; `cue export` still carries both fields, so a
// cross-language consumer keeps the XOR. Resolution of the source to a usable
// trust root is late-bound at verify time; this only carries the parsed form.
#Keyless: close({
	endpoints:     #KeylessEndpoints   @go(Endpoints)
	trustRoot?:    #TrustedRootReplica @go(TrustRoot,optional=nillable)
	trustRootRef?: #ImageRef           @go(TrustRootRef)
})

// SBOMSigner is a trusted signer of a base-image SBOM (ADR-040 D1, option ii).
// A base SBOM referrer is lifted to layer V only if its sigstore signature
// verifies against one of the lane's declared signers: the Fulcio
// certificate's OIDC issuer equals issuer and its SAN equals identity.
// Declaring a provider once covers every base SBOM that provider signs -- no
// per-SBOM digest pinning. The list is optional: a lane whose bases are fully
// catalogable in-process needs none. Fail-closed (enforced at pack time, a
// later instruction): a base SBOM matching no declared signer is rejected,
// never silently included. The sigstore trust root (Fulcio / Rekor / CT) is a
// verification-time parameter, not declared here.
#SBOMSigner: {
	@go(SBOMSigner)

	issuer:   string @go(Issuer)   // expected Fulcio cert OIDC issuer
	identity: string @go(Identity) // expected cert SAN (exact match)
}

// ---------------------------------------------------------------------------
// Path types -- canonical, composable hierarchy
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Step -- the union type
// ---------------------------------------------------------------------------

#Step: {
	@go(Step)
	id:             #Identifier @go(ID,type=string)
	image?:         #ImageRef   @go(Image,optional=nillable)
	imageFromStep?: #Identifier @go(ImageFromStep,type=string,optional=nillable)
	args: [...string] @go(Args)
	env: {
		[string]: string @go(Env)
	}
	inputs: [...#InputRef] @go(Inputs)
	output?: "image" @go(Output,type=string)
	outputs?: [...#FileOutput] @go(Outputs)
	secrets: [...#SecretRef] @go(Secrets)
	workdir?: #AbsPath @go(Workdir,optional=nillable)
	peers?: [...#Peer] @go(Peers)
	// forceRun: when true, strike bypasses the cache check
	// and runs the step unconditionally. The explicit escape
	// hatch for intentionally non-deterministic steps such as
	// `git clone` from a moving branch or `npm install` of a
	// `latest` tag. Strike does not auto-detect
	// non-determinism; lane authors declare it.
	forceRun?:   *false | bool   @go(ForceRun)
	timeout?:    #Duration       @go(Timeout,optional=nillable)
	pack?:       #PackSpec       @go(Pack,optional=nillable)
	deploy?:     #DeploySpec     @go(Deploy,optional=nillable)
	provenance?: #ProvenanceSpec @go(Provenance,optional=nillable)
	// constraint: exactly one of image, imageFrom, pack, or deploy -- validated in Go

	// D2 (ADR-039): a deploy step is a DAG leaf and declares no output.
	// Tying deploy presence to an empty outputs list keeps the constraint in
	// the schema (CUE first). It validates as an "incompatible list lengths"
	// error and is transparent to `cue exp gengotypes` (the generated Outputs
	// field is unchanged; verified by spike under cue v0.16.1). The
	// complementary leaf-edge rejection lives in lane.Build
	// (validateDeployLeaves).
	if deploy != _|_ {
		outputs: []
		output?: _|_
	}

	// A step declares the singular image output XOR file/directory outputs,
	// never both (ADR-046). When output is present, outputs must be empty; CUE
	// reports a conflict ("incompatible list lengths") otherwise. This is
	// transparent to gengotypes -- the generated Outputs field is unchanged --
	// and is the same idiom as the deploy-leaf constraint above (ADR-039).
	if output != _|_ {
		outputs: []
	}
}

// ---------------------------------------------------------------------------
// Image references
// ---------------------------------------------------------------------------

#ImageRef: =~"^.+@sha256:[a-f0-9]{64}$"

// StepImageRef references a step's image output by step alone: the image is
// addressed by step, never by an output name (ADR-046). Used in the
// deploy.artifacts.from disjunction.
#StepImageRef: {
	@go(StepImageRef)
	step: #Identifier @go(Step,type=string)
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

// A reference to a named output of a step earlier in this lane.
#OutputRef: {
	@go(OutputRef)
	step:   #Identifier @go(Step,type=string)
	output: #Identifier @go(Output,type=string)
}

#InputRef: {
	@go(InputRef)

	from:     #OutputRef @go(From)
	subpath?: #RelPath   @go(Subpath,optional=nillable) // path within producer output; nil mounts whole output
	mount:    #AbsPath   @go(Mount)
	digest?:  #Digest    @go(Digest,type=*Digest)
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#ArtifactType: "file" | "directory" | "image"

#FileArtifactType: "file" | "directory"

// FileOutput is a named file or directory output (plural outputs), referenced
// by inputs.from, pack.files.from, and deploy.artifacts.from as {step, output}.
#FileOutput: {
	@go(FileOutput)
	id:   #Identifier       @go(ID,type=string)
	type: #FileArtifactType @go(Type)
	// path is relative to the step workdir (the single writable volume).
	// Absent means the whole workdir is the artifact; a value selects a
	// subpath within it. An absolute path is a type error: outputs are
	// projections of the workdir, never of the read-only base image.
	path?: #RelPath @go(Path,optional=nillable)
}

// ---------------------------------------------------------------------------
// Network peers -- declared trust contracts (ADR-005, ADR-007)
// ---------------------------------------------------------------------------

// Peers are container-egress trust contracts: each declares a
// destination the step container may reach during execution,
// together with the trust anchor strike uses to verify that
// destination's identity. Two protocols are supported:
//   - HTTPS peers: mediated through strike's per-step TLS
//     mediator (ADR-028); the container's egress is restricted to
//     declared peers and their connections are attested.
//   - SSH peers: known_hosts injection and ssh-agent-proxy
//     forwarding (ADR-024, ADR-025), with egress restricted to
//     declared peers via per-peer capsule forwards (ADR-033).
//
// There is no OCI peer type. A step's own image is pulled
// controller-side and verified against its pinned digest
// (#ImageRef); the digest is the integrity anchor, so no peer
// declaration is needed for it. A container that itself performs
// registry operations (DinD) reaches the registry over HTTPS and
// declares it as an HTTPS peer. See ADR-029.
//
// Peer is a discriminated union over the supported protocols. A
// non-empty peers list enumerates the destinations the step may
// reach; an absent or empty list yields an empty-allowlist capsule
// that permits no egress (ADR-033). Peers flow into the deploy
// attestation.
#Peer: (#HTTPSPeer | #SSHPeer) @go(-)

// HTTPSPeer declares an HTTPS endpoint together with its server-trust anchor.
#HTTPSPeer: {
	@go(HTTPSPeer)
	type:  "https"   @go(Type)
	host:  #Host     @go(Host,type="github.com/istr/strike/internal/transport".Host)
	trust: #TLSTrust @go(Trust,type="github.com/istr/strike/internal/transport".TLSTrust)
}

// SSHPeer declares an SSH endpoint with explicit known_hosts entries.
// Strike creates and injects a global known_hosts entry in the
// step container.
// For client-side authentication, strike forwards an ssh-agent socket
// if available.
#SSHPeer: {
	@go(SSHPeer)
	type: "ssh" @go(Type)
	host: #Host @go(Host,type="github.com/istr/strike/internal/transport".Host)
	knownHosts: [...#KnownHostEntry] @go(KnownHosts)
}

// KnownHostEntry is one server key, an OpenSSH known_hosts line
// decomposed into typed fields.
#KnownHostEntry: {
	@go(KnownHostEntry)
	keyType: "ssh-ed25519" | "ecdsa-sha2-nistp256" |
		"rsa-sha2-512" | "rsa-sha2-256" @go(KeyType)
	// key is the base64-encoded public key body (no PEM armor).
	key: =~"^[A-Za-z0-9+/]+={0,2}$" @go(Key)
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

#SecretSource: =~"^(env|file)://.+"

#SecretRef: {
	@go(SecretRef)
	name: string @go(Name)
	env:  string @go(Env)
}

// ---------------------------------------------------------------------------
// Pack -- deterministic OCI image assembly
// ---------------------------------------------------------------------------

#PackSpec: {
	@go(PackSpec)
	base: #ImageRef @go(Base)
	files: [...#PackFile] @go(Files)
	packages?: [...#Package] @go(Packages)
	configFiles?: {
		[Path=string]: #FileEntry @go(ConfigFiles)
	}
	config?: #ImageConfig @go(Config,optional=nillable)
	annotations?: {
		[string]: string @go(Annotations)
	}
	sbom?: #SBOMConfig @go(SBOM,optional=nillable)
	push?: [...string] @go(Push)
}

#PackFile: {
	@go(PackFile)
	from: #OutputRef   @go(From)
	dest: #AbsPath     @go(Dest)
	mode: *0o755 | int @go(Mode)
	uid?: int          @go(UID,optional=nillable)
	gid?: int          @go(GID,optional=nillable)
}

#Package: {
	@go(Package)
	name:     string @go(Name)
	version?: string @go(Version,optional=nillable)
}

#FileEntry: {
	@go(FileEntry)
	content: string       @go(Content)
	mode:    *0o644 | int @go(Mode)
	uid:     *0 | int     @go(UID)
	gid:     *0 | int     @go(GID)
}

#ImageConfig: {
	@go(ImageConfig)
	env?: {
		[string]: string @go(Env)
	}
	entrypoint?: [...string] @go(Entrypoint)
	cmd?: [...string] @go(Cmd)
	workdir?: #AbsPath @go(Workdir,optional=nillable)
	user?:    string   @go(User,optional=nillable)
	labels?: {
		[string]: string @go(Labels)
	}
}

// ---------------------------------------------------------------------------
// Deploy -- apply to target, mandatory state recording
// ---------------------------------------------------------------------------

#DeploySpec: {
	@go(DeploySpec)
	method: #DeployMethod @go(Method)
	artifacts: {
		[ID=#Identifier]: #ArtifactRef
	} @go(Artifacts,type=map[string]ArtifactRef)
	target:    #DeployTarget   @go(Target)
	recording: #StateRecording @go(Recording)
	source?: {
		gitImage: #ImageRef
	} @go(Source,optional=nillable)
}

#DeployMethod: (#DeployKubernetes | #DeployRegistry | #DeployCustom) @go(-)

#DeployKubernetes: {
	@go(DeployKubernetes)
	type:      "kubernetes"                     @go(Type)
	image:     #ImageRef                        @go(Image)
	namespace: string                           @go(Namespace)
	strategy:  *"apply" | "replace" | "rollout" @go(Strategy)
	// kubeconfig is a host-side path to a kubeconfig file, resolved by
	// ResolveKubeconfig (explicit value, then $KUBECONFIG, then the
	// default). It is intentionally unconstrained: host paths may be
	// relative or contain "..", and are not the forward-slash container
	// paths that #AbsPath / #RelPath model.
	kubeconfig?: string @go(Kubeconfig,optional=nillable)
}

#DeployRegistry: {
	@go(DeployRegistry)
	type: "registry" @go(Type)
	// source and target are registry image references (the copy source and
	// destination), not filesystem paths; they flow to registry.CopyImage.
	source: string @go(Source)
	target: string @go(Target)
}

#DeployCustom: {
	@go(DeployCustom)
	type:  "custom"  @go(Type)
	image: #ImageRef @go(Image)
	args: [...string] @go(Args)
	env: {
		[string]: string @go(Env)
	}
	entrypoint?: [...string] @go(Entrypoint)
}

// ArtifactSource is the deploy-artifact reference: a step's image (by step) or
// a named file/directory output (by step+output). @go(-) -- the generator skips
// the disjunction; artifact_source.go provides the Go discriminated union and
// ArtifactRef.UnmarshalJSON, the same pattern as DeployMethod and Peer.
//
// The image arm carries no discriminator field, so a bare {step} unifies with
// both arms; the default marker (*) resolves that ambiguity to StepImageRef
// under the concrete-validation pass (parse.go validates with
// cue.Concrete(true), which rejects an unresolved disjunction). When the output
// field is present the OutputRef arm is the more specific match and is selected
// over the default.
#ArtifactSource: (*#StepImageRef | #OutputRef) @go(-)

#ArtifactRef: {
	@go(ArtifactRef)
	from: #ArtifactSource @go(From)
}

#DeployTarget: {
	@go(DeployTarget)

	// Stable identifier assigned at authoring time. External verifiers use
	// this to pair pre/post-state digests across consecutive deploys
	// to the same target.
	id:          #Identifier @go(ID,type=string)
	type:        string      @go(Type)
	description: string      @go(Description)
	url?:        string      @go(URL,optional=nillable)
	namespace?:  string      @go(Namespace,optional=nillable)
}

// ---------------------------------------------------------------------------
// State recording: pre/post captures are the input to the recording
// operation. The output carries two digests (pre_state_digest,
// post_state_digest). No detection, no drift policy -- see ADR-016.
// ---------------------------------------------------------------------------

#StateRecording: {
	@go(StateRecording)
	preState:  #CaptureSet @go(PreState)
	postState: #CaptureSet @go(PostState)
}

#CaptureSet: {
	@go(CaptureSet)

	// required means the capture must run successfully for the recording to be
	// valid -- execution success, not a drift reaction. strike takes no action
	// on state differences (ADR-016); do not add policy fields here.
	required: *true | bool @go(Required)
	captures: [...#Capture] @go(Captures)
}

#Capture: {
	@go(Capture)
	id:    #Identifier @go(ID,type=string)
	image: #ImageRef   @go(Image)
	command: [...string] @go(Command)
	peers?: [...#Peer] @go(Peers)
	mounts?: [...#CaptureMount] @go(Mounts)
}

#CaptureMount: {
	@go(CaptureMount)

	// source is an engine mount source -- the produced image or named
	// storage the engine resolves -- not a host path. target is the
	// absolute mount point inside the capture container.
	source: string   @go(Source)
	target: #AbsPath @go(Target)
}

// ---------------------------------------------------------------------------
// Provenance declaration
// ---------------------------------------------------------------------------

// ProvenanceSpec declares that a step produces a source-provenance
// record at a specific path inside its container, in a specific format.
// After step exit, strike reads the file, validates against the schema
// for the declared type, and stores the resulting record in lane state.
//
// path is the provenance file, relative to the step workdir.
#ProvenanceSpec: {
	@go(ProvenanceSpec)
	type: "git" | "tarball" | "oci" | "url" @go(Type)
	// path is the provenance file, relative to the step workdir.
	path: #RelPath @go(Path)
}

// ---------------------------------------------------------------------------
// Supply chain types
// ---------------------------------------------------------------------------

#SBOMConfig: {
	@go(SBOMConfig)
	generate: *true | bool                    @go(Generate)
	format:   *"spdx-json" | "cyclonedx-json" @go(Format)
}

#Digest: =~"^sha256:[a-f0-9]{64}$" @go(-)

#Duration: =~"^[0-9]+(s|m|h)$"
