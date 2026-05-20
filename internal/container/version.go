package container

import (
	"fmt"
	"strconv"
	"strings"
)

// RequireVersion verifies that the engine's reported version is at
// least minVersion. The version string comes from
// engine.Identity().Runtime.Version, populated by a prior
// successful engine.Info call.
//
// Returns an error if Info has not run (Identity or Runtime nil),
// if the version is empty or unparseable, or if it is below
// minVersion.
//
// Comparison is dotted-decimal major.minor.patch on the leading
// three components. Suffixes like "5.4.2+ds1" or "5.0.0-rc1" are
// tolerated: parsing stops at the first non-digit, non-dot char.
func RequireVersion(engine Engine, minVersion string) error {
	id := engine.Identity()
	if id == nil {
		return fmt.Errorf("container engine: identity unavailable (Ping not called)")
	}
	if id.Runtime == nil {
		return fmt.Errorf("container engine: runtime info unavailable (Info not called or failed)")
	}
	have := id.Runtime.Version
	if have == "" {
		return fmt.Errorf("container engine: empty version string from engine")
	}
	haveParts, err := parseVersion(have)
	if err != nil {
		return fmt.Errorf("container engine: parse engine version %q: %w", have, err)
	}
	wantParts, err := parseVersion(minVersion)
	if err != nil {
		return fmt.Errorf("container engine: parse required version %q: %w", minVersion, err)
	}
	if compareVersions(haveParts, wantParts) < 0 {
		return fmt.Errorf("container engine: version %s is below required %s; "+
			"strike requires Podman %s or later (see docs/SPIKE-rootless-netns-backend.md)",
			have, minVersion, minVersion)
	}
	return nil
}

func parseVersion(s string) ([3]int, error) {
	var out [3]int
	end := 0
	for end < len(s) {
		c := s[end]
		if (c < '0' || c > '9') && c != '.' {
			break
		}
		end++
	}
	s = s[:end]
	parts := strings.Split(s, ".")
	if len(parts) == 0 || parts[0] == "" {
		return out, fmt.Errorf("no numeric components")
	}
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return out, fmt.Errorf("component %d: %w", i, err)
		}
		out[i] = n
	}
	return out, nil
}

func compareVersions(a, b [3]int) int {
	for i := range 3 {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
