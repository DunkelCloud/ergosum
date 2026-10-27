//go:build !unix

package authority

// withUmask runs fn; this platform has no umask.
func withUmask(_ int, fn func() error) error { return fn() }
