// pipeline/schema.cue
package pipeline

@go(pipeline) // generated go package name

// Enforce digest format - no tag alias possible
#ImageRef: =~"^.+@sha256:[a-f0-9]{64}$"

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
    name: string @go(Name) // references pipeline.secrets
    env:  string @go(Env)  // environment variable in the container
}

#Step: {
    @go(Step)
    name:     string @go(Name)
    image:    #ImageRef @go(Image)
    args:     [...string] @go(Args)
    inputs:   [...#InputRef] @go(Inputs)
    sources:  [...#SourceRef] @go(Sources)
    outputs:  [...#OutputSpec] @go(Outputs)
    secrets:  [...#SecretRef] @go(Secrets)
}

#Pipeline: {
    @go(Pipeline)
    registry: string & =~"^[a-z0-9./-]+" @go(Registry)
    secrets:  [string]: #SecretSource @go(Secrets)
    steps:    [#Step, ...#Step] @go(Steps) // at least one step
}
