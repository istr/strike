package registry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ggcrtransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/istr/strike/internal/clock"
)

// servedBound is the longest the read-after-write waits, all waits added,
// for a registry to serve what a deploy pushed (ADR-051 amendment
// 2026-11-08).
const servedBound = clock.Minute

// ConfirmServed confirms by read-after-write that the registry serves what a
// deploy pushed to repo (ADR-051 amendment 2026-11-08): the subject manifest
// and every referrer in referrers answer a manifest HEAD, and the filtered
// referrers listing of each artifact type among referrers holds every
// referrer of that type. A registry may serve a write late, so a read that
// finds a manifest not served yet is repeated after a wait that starts at one
// second and doubles, the last wait cut so the waits add up to servedBound.
// wait is the interruptible wait between reads, clock.Wait in production. Any
// other failure ends the confirmation at once: a refusal is not a manifest
// served late. Every read goes through rt.
func ConfirmServed(ctx context.Context, rt http.RoundTripper, repo string, subject v1.Hash, referrers []v1.Descriptor, wait func(context.Context, clock.Duration) error) error {
	r, err := name.NewRepository(repo)
	if err != nil {
		return fmt.Errorf("read-after-write %s: %w", repo, err)
	}
	reg := r.RegistryStr()
	backoff, waited := clock.Second, clock.Duration(0)
	for {
		missing, readErr := unserved(ctx, rt, r, subject, referrers)
		if readErr != nil {
			return fmt.Errorf("registry %s: subject %s: read-after-write: %w", reg, subject, readErr)
		}
		if len(missing) == 0 {
			return nil
		}
		if waited >= servedBound {
			return fmt.Errorf("registry %s: subject %s: not served after %s: %s", reg, subject, servedBound, strings.Join(missing, ", "))
		}
		d := min(backoff, servedBound-waited)
		log.Printf("WAIT   registry %s: %d of %d manifests not served yet, next read in %s", reg, len(missing), len(referrers)+1, d)
		if waitErr := wait(ctx, d); waitErr != nil {
			return fmt.Errorf("registry %s: subject %s: read-after-write: %w", reg, subject, waitErr)
		}
		waited += d
		backoff *= 2
	}
}

// unserved reads once what ConfirmServed confirms and returns, each once and
// in the order of the subject and then referrers, the digest of every
// manifest not served yet: a manifest whose HEAD answers 404, or a referrer
// the filtered listing of its artifact type does not hold. Any other failure
// is an error.
func unserved(ctx context.Context, rt http.RoundTripper, repo name.Repository, subject v1.Hash, referrers []v1.Descriptor) ([]string, error) {
	var missing []string
	served, err := headServed(ctx, rt, repo.Digest(subject.String()))
	if err != nil {
		return nil, err
	}
	if !served {
		missing = append(missing, subject.String())
	}
	listed := map[string]map[v1.Hash]bool{}
	for _, d := range referrers {
		if listed[d.ArtifactType] == nil {
			set, listErr := listReferrers(ctx, rt, repo.Digest(subject.String()), d.ArtifactType)
			if listErr != nil {
				return nil, listErr
			}
			listed[d.ArtifactType] = set
		}
		served, err = headServed(ctx, rt, repo.Digest(d.Digest.String()))
		if err != nil {
			return nil, err
		}
		if !served || !listed[d.ArtifactType][d.Digest] {
			missing = append(missing, d.Digest.String())
		}
	}
	return missing, nil
}

// headServed reports whether the registry answers a manifest HEAD for ref. A
// 404 is a manifest not served yet; any other failure is an error.
func headServed(ctx context.Context, rt http.RoundTripper, ref name.Digest) (bool, error) {
	_, err := remote.Head(ref, remote.WithTransport(rt), remote.WithContext(ctx))
	var terr *ggcrtransport.Error
	if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("head %s: %w", ref.DigestStr(), err)
	}
	return true, nil
}

// listReferrers returns the digests the referrers listing of subject holds
// under the artifactType filter. The referrers tag fallback is refused, as on
// every write: a registry without the referrers API fails the read.
func listReferrers(ctx context.Context, rt http.RoundTripper, subject name.Digest, artifactType string) (map[v1.Hash]bool, error) {
	idx, err := remote.Referrers(subject,
		remote.WithFilter("artifactType", artifactType),
		remote.WithReferrersTagFallback(false),
		remote.WithContext(ctx),
		remote.WithTransport(rt))
	if err != nil {
		return nil, fmt.Errorf("list %s referrers: %w", artifactType, err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("%s referrers index: %w", artifactType, err)
	}
	set := make(map[v1.Hash]bool, len(im.Manifests))
	for _, m := range im.Manifests {
		set[m.Digest] = true
	}
	return set, nil
}
