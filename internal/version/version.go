// Package version carries build metadata injected via -ldflags.
package version

// Set at build time:
//
//	-X github.com/DunkelCloud/ergosum/internal/version.Version=v0.1.0
//	-X github.com/DunkelCloud/ergosum/internal/version.Commit=<sha>
var (
	Version = "dev"
	Commit  = "unknown"
)

// String returns a one-line version description.
func String() string {
	return Version + " (" + Commit + ")"
}
