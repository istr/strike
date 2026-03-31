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
	network: *false | bool @go(Network)
	timeout: *"10m" | #Duration @go(Timeout)
}

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
	sources:     [...#SourceRef] @go(Sources)
	outputs:     [...#OutputSpec] @go(Outputs)
	secrets:     [...#SecretRef] @go(Secrets)
	network?:    bool @go(Network)
	timeout?:    #Duration @go(Timeout)
	pack?:       #PackSpec @go(Pack,optional=nillable)
	deploy?:     #DeploySpec @go(Deploy,optional=nillable)
	// constraint: exactly one of image, image_from, pack, or deploy — validated in Go
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
	mount:   string & =~"^/" @go(Mount)
	digest?: #Digest @go(Digest)
}

#SourceRef: {
	@go(SourceRef)
	path:    string @go(Path)
	mount:   string & =~"^/" @go(Mount)
	digest?: #Digest @go(Digest)
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#ArtifactType: "file" | "directory" | "image"

#OutputSpec: {
	@go(OutputSpec)
	name:      string @go(Name)
	type:      #ArtifactType @go(Type)
	path:      string @go(Path)
	expected?: #OutputValidation @go(Expected,optional=nillable)
}

#OutputValidation: {
	@go(OutputValidation)
	content_type?: string @go(ContentType)
	min_size?:     int @go(MinSize)
	max_size?:     int @go(MaxSize)
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
	dest: string & =~"^/" @go(Dest)
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
}

#DeployMethod: #DeployKubernetes | #DeployRegistry | #DeployCustom

#DeployKubernetes: {
	@go(DeployKubernetes)
	type:      "kubernetes" @go(Type)
	namespace: string @go(Namespace)
	strategy:  *"apply" | "replace" | "rollout" @go(Strategy)
}

#DeployRegistry: {
	@go(DeployRegistry)
	type:   "registry" @go(Type)
	source: string @go(Source)
	target: string @go(Target)
}

#DeployCustom: {
	@go(DeployCustom)
	type:  "custom" @go(Type)
	image: #ImageRef @go(Image)
	args:  [...string] @go(Args)
	env:   [string]: string @go(Env)
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
	name:      string @go(Name)
	type:      "command" | "kubernetes" | "http" @go(Type)
	command?:  [...string] @go(Command)
	resource?: #KubeResource @go(Resource,optional=nillable)
	url?:      string @go(URL)
}

#KubeResource: {
	@go(KubeResource)
	kind:       string @go(Kind)
	name:       string @go(Name)
	namespace?: string @go(Namespace)
	jsonpath?:  string @go(JSONPath)
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

#Digest: =~"^sha256:[a-f0-9]{64}$"
#Duration: =~"^[0-9]+(s|m|h)$"
