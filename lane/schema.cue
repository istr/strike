// lane/schema.cue
package lane

@go(lane) // generated go package name

// Enforce digest format - no tag alias possible
#ImageRef: =~"^.+@sha256:[a-f0-9]{64}$"

// Local image tag — digest resolved at runtime via podman inspect.
// Only valid for bootstrap roots (DAG entry points without image_from).
#LocalImageRef: =~"^[a-z0-9][a-z0-9./_-]*(:[a-zA-Z0-9._-]+)?$"

// Reference to an OCI image produced by a previous step
#ImageFrom: {
    @go(ImageFrom)
    step:   string @go(Step)   // producing step name
    output: string @go(Output) // output name (must be oci-tar)
}

#ArtifactType: "file" | "directory" | "oci-tar"

#SecretSource: =~"^(env|file|op)://.+"

#InputRef: {
    @go(InputRef)
    name:  string @go(Name)
    from:  string @go(From)
    mount: string & =~"^/" @go(Mount) // absolute path
}

#SourceRef: {
    @go(SourceRef)
    path:  string @go(Path)            // relative to work directory
    mount: string & =~"^/" @go(Mount)
}

#OutputSpec: {
    @go(OutputSpec)
    name: string @go(Name)
    type: #ArtifactType @go(Type)
    path: string & =~"^/" @go(Path)
}

#SecretRef: {
    @go(SecretRef)
    name: string @go(Name) // references lane.secrets
    env:  string @go(Env)  // environment variable in the container
}

#Step: {
    @go(Step)
    name:        string @go(Name)
    image?:      (#ImageRef | #LocalImageRef) @go(Image)  // pinned or local image
    image_from?: #ImageFrom @go(ImageFrom,optional=nillable) // image from previous step output
    args:        [...string] @go(Args)
    inputs:      [...#InputRef] @go(Inputs)
    sources:     [...#SourceRef] @go(Sources)
    outputs:     [...#OutputSpec] @go(Outputs)
    secrets:     [...#SecretRef] @go(Secrets)
    // constraint: exactly one of image or image_from — validated in Go
}

#Lane: {
    @go(Lane)
    registry: string & =~"^[a-z0-9./-]+" @go(Registry)
    secrets:  [string]: #SecretSource @go(Secrets)
    steps:    [#Step, ...#Step] @go(Steps) // at least one step
}
