package deploy

import "github.com/istr/strike/internal/primitive"

// strikeVersion is the version of strike (ADR-060 D1): a constant of the
// source, compiled in. No linker flag, build argument or version-control
// stamp carries or changes it. On main the value is the development version;
// a release commit changes this file and no other (ADR-060 D3, D4). The file
// holds the constant and nothing else.
const strikeVersion primitive.SemVer = "0.0.0-devel"
