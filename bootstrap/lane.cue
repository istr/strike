// The bootstrap lane of the reproducibility proof
// (docs/ADR-009-bootstrap-reproducibility-proof.md), as a template. The
// stage_0 build of bootstrap/Containerfile renders it with
//
//	go tool cue export ./bootstrap -e out --out yaml
//
// from two inputs it copies into bootstrap/input/: HEAD, the commit the build
// fetched, which becomes the source step's revision, and caddy-root.crt, the
// root of the local sigstore harness, which anchors every harness endpoint.
// Unifying with lane.#Lane checks the rendered lane against the schema before
// it is written.
//
// The lane is the workstation proof: it fetches the commit, downloads the Go
// modules in the one step that reaches the network for them, builds the
// strike binary and image twice without network, the second time with the
// cache bypassed, and deploys the first image to the harness registry under
// the harness keyless chain only if the reproducedBy gate finds both images
// identical.
@extern(embed)

package bootstrap

import (
	"list"
	"strings"

	"github.com/istr/strike/contract/lane"
)

// _head is .git/HEAD after the checkout of FETCH_HEAD: one full commit hash.
_head: string @embed(file=input/HEAD, type=text)
_head: =~"^[0-9a-f]{40}\n?$"

// _caddyPEM is the harness root as the harness exports it: exactly one PEM
// certificate block.
_caddyPEM: string @embed(file=input/caddy-root.crt, type=text)
_caddyPEM: =~"^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?$"

_revision:  strings.TrimSpace(_head)
_pemLines:  strings.Split(strings.TrimSpace(_caddyPEM), "\n")
_caddyRoot: strings.Join(list.Slice(_pemLines, 1, len(_pemLines)-1), "")

// Public roots, each verified on its own against the live endpoint: SSL.com
// Root Certification Authority ECC for the DoT resolver, USERTrust ECC
// Certification Authority for github.com, and GTS Root R4 for every Google
// host the fetch step reaches. GTS Root R1 anchors cgr.dev and GTS Root R4
// also the storage host cgr.dev redirects blob reads to; both are the roots
// the live chains of those hosts were measured to verify to.
_rootDoT:    "MIICjTCCAhSgAwIBAgIIdebfy8FoW6gwCgYIKoZIzj0EAwIwfDELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQKDA9TU0wgQ29ycG9yYXRpb24xMTAvBgNVBAMMKFNTTC5jb20gUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBFQ0MwHhcNMTYwMjEyMTgxNDAzWhcNNDEwMjEyMTgxNDAzWjB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8GA1UEAwwoU1NMLmNvbSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IEVDQzB2MBAGByqGSM49AgEGBSuBBAAiA2IABEVuqVDEpiM2nl8ojRfLliJkP9x6jh3MCLOicSS6jkm5BBtHllirLZXI7Z4INcgn64mMU1jrYor+8FsPazFSY0E7ic3s7LaNGdM0B9y7xgZ/wkWV7Mt/qCPgCemB+vNH06NjMGEwHQYDVR0OBBYEFILRhXMw5zUE044CkvvlpNHEIejNMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUgtGFczDnNQTTjgKS++Wk0cQh6M0wDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA2cAMGQCMG/n61kRpGDPYbCWe+0F+S8Tkdzt5fxQaxFGRrMcIQBiu77D5+jNB5n5DQtdcj7EqgIwH7y6C+IwJPt8bYBVCpk+gA0z5Wajs6O7pdWLjwkspl1+4vAHCGht0nxpbl/f5Wpl"
_rootGitHub: "MIICjzCCAhWgAwIBAgIQXIuZxVqUxdJxVt7NiYDMJjAKBggqhkjOPQQDAzCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMjAxMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQarFRaqfloI+d61SRvU8Za2EurxtW20eZzca7dnNYMYf3boIkDuAUU7FfO7l0/4iGzzvfUinngo4N+LZfQYcTxmdwlkWOrfzCjtHDix6EznPO/LlxTsV+zfTJ/ijTjeXmjQjBAMB0GA1UdDgQWBBQ64QmG1M8ZwpZ2dEl23OA1xmNjmjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjA2Z6EWCNzklwBBHU6+4WMBzzuqQhFkoJ2UOQIReVx7Hfpkue4WQrO/isIJxOzksU0CMQDpKmFHjFJKS04YcPbWRNZu9YO6bVi9JNlWSOrvxKJGgYhqOkbRqZtNyWHa0V1Xahg="
_rootGTSR1:  "MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7wCl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjwTcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0PfyblqAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaHszVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmkMiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70paDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrNVjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibbC5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEeQkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuyh6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM47HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8JZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6EfMgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bbbP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c"
_rootGTSR4:  "MIICCTCCAY6gAwIBAgINAgPlwGjvYxqccpBQUjAKBggqhkjOPQQDAzBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjQwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATzdHOnaItgrkO4NcWBMHtLSZ37wWHO5t5GvWvVYRg1rkDdc/eJkTBa6zzuhXyiQHY7qca4R9gq55KRanPpsXI5nymfopjTX15YhmUPoYRlBtHci8nHc8iMai/lxKvRHYqjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSATNbrdP9JNqPV2Py1PsVq8JQdjDAKBggqhkjOPQQDAwNpADBmAjEA6ED/g94D9J+uHXqnLrmvT/aDHQ4thQEd0dlq7A/Cr8deVl5c1RxYIigL9zC2L7F8AjEA8GE8p/SgguMh1YQdc4acLa/KNJvxn7kjNuK8YAOdgLOaVsjh4rsUecrNIdSUtUlD"

_goImage:     "cgr.dev/chainguard/go@sha256:2ed63c9db04ba7d7e4d426ffd17afe1793df837f18194ddc251d15e90977a00b"
_staticImage: "cgr.dev/chainguard/static@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9"

// _goOffline is the environment of the Go steps that run without network:
// the toolchain is the image's, every module comes from the fetch step's
// read-only module cache, and caches and temporary files stay below
// /work/src, the directory the input seed creates for the step.
_goOffline: {
	GOTOOLCHAIN: "local"
	GOPROXY:     "off"
	GOCACHE:     "/work/src/gocache"
	GOMODCACHE:  "/gomodcache"
	GOTMPDIR:    "/work/src"
}

_modcacheInput: {
	from: {step: "fetch", output: "modcache"}
	mount: "/gomodcache"
}

_build: {
	image: _goImage
	args: ["-C", "/work/src/tree", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", "/work/src/strike", "./cmd/strike"]
	workdir: "/work"
	env: _goOffline & {CGO_ENABLED: "0"}
	inputs: [
		{from: {step: "generate", output: "tree"}, mount: "/work/src/tree"},
		_modcacheInput,
	]
	secrets: []
	outputs: [{id: "binary", type: "file", path: "src/strike"}]
}

_pack: {
	_from: string
	pack: {
		base: _staticImage
		files: [{from: {step: _from, output: "binary"}, dest: "/usr/bin/strike", mode: 0o755}]
	}
	args: []
	env: {}
	inputs: []
	secrets: []
	output: "image"
}

out: lane.#Lane & {
	name: "strike-bootstrap"
	id:   "strike-bootstrap"
	secrets: {
		"builder-token":  "env://SIGSTORE_ID_TOKEN"
		"registry-token": "env://REGISTRY_ID_TOKEN"
	}

	resolver: {
		adn: "one.one.one.one"
		ip:  "1.1.1.1"
		trust: cert: _rootDoT
	}
	oidc: {
		issuer:   "https://keycloak.127.0.0.1.sslip.io:8443/realms/sigstore"
		audience: "sigstore"
		identity: "https://forge.strike.localhost/istr/strike/bootstrap/lane.cue@refs/heads/main"
		extensions: sourceRepositoryRef: "refs/heads/main"
		token: "builder-token"
		trust: cert: _caddyRoot
	}
	keyless: endpoints: {
		fulcio: {url: "https://fulcio.127.0.0.1.sslip.io:5555", trust: cert: _caddyRoot}
		rekor: {url: "https://rekor.127.0.0.1.sslip.io:3003", trust: cert: _caddyRoot}
		tsa: {url: "https://tsa.127.0.0.1.sslip.io:3004", trust: cert: _caddyRoot}
	}
	registries: [{
		registry: {host: "cgr.dev", trust: cert: _rootGTSR1}
		storages: [{host: "9236a389bd48b984df91adc1bc924620.r2.cloudflarestorage.com", trust: cert: _rootGTSR4}]
	}]

	steps: [
		{
			// The committer and author identity keep git from deriving one
			// from the container hostname, which would be a DNS query.
			id:    "source"
			image: "cgr.dev/chainguard/git@sha256:f5f91faa60ed1b69deab0546d2154d2150f5f9163843793e72d45c51ff27153e"
			args: ["clone", "--revision=" + _revision, "--depth=1", "--separate-git-dir=/out/git", "https://github.com/istr/strike", "/out/tree"]
			workdir: "/out"
			env: {
				GIT_COMMITTER_NAME:  "strike"
				GIT_COMMITTER_EMAIL: "strike@invalid"
				GIT_AUTHOR_NAME:     "strike"
				GIT_AUTHOR_EMAIL:    "strike@invalid"
			}
			inputs: []
			secrets: []
			peers: [{type: "https", host: "github.com", trust: cert: _rootGitHub}]
			outputs: [{id: "tree", type: "directory", path: "tree"}]
		},
		{
			// The module proxy hands some module zips to Google Cloud Storage
			// by redirect, so this step declares both hosts. The checksum
			// database is not declared: go.sum covers every module, and a
			// gap fails the step instead of being filled from the network.
			id:    "fetch"
			image: _goImage
			args: ["-C", "/work/src/tree", "mod", "download", "-x"]
			workdir: "/work"
			env: {
				GOTOOLCHAIN: "local"
				GOFLAGS:     "-modcacherw"
				GOCACHE:     "/work/src/gocache"
				GOMODCACHE:  "/work/src/gomodcache"
				GOTMPDIR:    "/work/src"
			}
			inputs: [{from: {step: "source", output: "tree"}, mount: "/work/src/tree"}]
			secrets: []
			peers: [
				{type: "https", host: "proxy.golang.org", trust: cert: _rootGTSR4},
				{type: "https", host: "storage.googleapis.com", trust: cert: _rootGTSR4},
			]
			outputs: [{id: "modcache", type: "directory", path: "src/gomodcache"}]
		},
		{
			id:    "generate"
			image: _goImage
			args: ["-C", "/work/src/tree", "generate", "./contract"]
			workdir: "/work"
			env:     _goOffline
			inputs: [
				{from: {step: "source", output: "tree"}, mount: "/work/src/tree"},
				_modcacheInput,
			]
			secrets: []
			outputs: [{id: "tree", type: "directory", path: "src/tree"}]
		},
		_build & {id: "build-binary"},
		_pack & {id: "build-image", _from: "build-binary"},
		_build & {id: "build-binary-2", forceRun: true},
		_pack & {id: "build-image-2", _from: "build-binary-2"},
		{
			id: "publish"
			deploy: {
				method: {
					type:         "registry"
					reproducedBy: "build-image-2"
					target: {
						host: "registry.127.0.0.1.sslip.io:5443"
						trust: cert: _caddyRoot
						name: "istr/strike"
						credential: {type: "bearer", token: "registry-token"}
					}
				}
				artifacts: strike: step: "build-image"
				recording: {
					preState: {required: false, captures: []}
					postState: {required: false, captures: []}
				}
			}
			args: []
			env: {}
			inputs: []
			secrets: []
			outputs: []
		},
	]
}
