# Execution order (global, cross-arc)

Items run top to bottom; order is line order. Each line is `- <item-id>`.
Items not listed here are unscheduled. `rank` orders items *within* an arc
for queries; this file is the cross-arc truth for *what runs next*. IDs only
-- titles live in the item files (single source).

# === BETA CUT: everything above item-0062 must land before the first tag ===
# 0063 first: stand up the make-check gate so all following merges are gated
#   (resolve the A/B design fork before authoring the instruction).
# 0035 next: fix the Containerfile codegen drift under the new gate; unblocks
#   the tag (item-0062 is blocked on it).
# 0064 (+0051 bundled): repair doc links AND write the deferred-limitation
#   notes for item-0003 and item-0015, which are post-beta.
# 0062 last: cut the tag and re-validate the README bootstrap end to end.
- item-0063
- item-0035
- item-0064
- item-0051
- item-0062
# === POST-BETA: internal hardening, conformance, and deferred posture work ===
- item-0074
- item-0086
- item-0087
- item-0088
- item-0092
- item-0090
- item-0091
- item-0045
- item-0050
- item-0052
- item-0057
- item-0075
- item-0076
- item-0077
- item-0085
- item-0055
- item-0056
- item-0078
- item-0079
- item-0049
- item-0080
- item-0081
- item-0082
- item-0083
- item-0084
- item-0089
- item-0027
- item-0016
- item-0004
- item-0005
- item-0002
- item-0003
- item-0015
- item-0006
- item-0007
- item-0008
- item-0009
- item-0010
- item-0011
- item-0012
- item-0093
