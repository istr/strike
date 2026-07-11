# Execution order (global, cross-arc)

Items run top to bottom; order is line order. Each line is `- <item-id>`.
Items not listed here are unscheduled. `rank` orders items *within* an arc
for queries; this file is the cross-arc truth for *what runs next*. IDs only
-- titles live in the item files (single source).

# === BETA CUT: public-announcement bar -- all promises MET, exhaustively type-clean, no Makefile ===
# 0063  dogfood strike lane (option B) -- the gate that REPLACES `make check`.
# 0035  retire cue codegen/fmt Makefile targets (also repairs the broken bootstrap).
# --- full type-cleanliness arc (by rank): clean tree, then graduate the flow gate ---
# 0045 0075 0090 0091 0076 0077 0085 0078 0086 0087 0088 0079 0080 0092 0081 0082 0089 0083
#   retire every typed-site class; 0090 owns the sites 0074's cuelint gate flags red.
# 0084  graduate linttypeflow standalone -> aggregate (green, allowlist-free).
# --- build-toolchain endgame: every gate now go-native and green ---
# 0093  fold the two Go-type linters into gotypelint golangci analyzers (needs 0084's settled surface).
# 0094  make the cuelint gate go-native (needs 0090).  0095 replace shell gates.
# 0097  retire the sigstore-local Makefile.
# 0096  CAPSTONE: delete the root Makefile into the green dogfood gate; migrate the docs.
# --- promise proofs + docs ---
# 0006 base-SBOM E2E; 0007 cosign independent; 0011 verify enforces SCT.  0064(+0051) README true.
# 0062  cut the tag + live E2E re-validation.  <- THE TAG (clean tree, no Makefile)
- item-0063
- item-0035
- item-0045
- item-0075
- item-0090
- item-0091
- item-0076
- item-0077
- item-0085
- item-0078
- item-0086
- item-0087
- item-0088
- item-0079
- item-0080
- item-0092
- item-0081
- item-0082
- item-0089
- item-0083
- item-0084
- item-0093
- item-0094
- item-0095
- item-0097
- item-0096
- item-0006
- item-0007
- item-0011
- item-0064
- item-0051
- item-0062
# === POST-BETA: cue-coverage, test-hygiene, dns, output-model, engine, ssh-front, sigstore/ct harness, parked ===
- item-0050
- item-0052
- item-0057
- item-0055
- item-0056
- item-0049
- item-0027
- item-0016
- item-0004
- item-0005
- item-0002
- item-0003
- item-0015
- item-0008
- item-0009
- item-0010
- item-0012
