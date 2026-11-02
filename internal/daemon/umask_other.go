//go:build !unix

package daemon

// withUmask runs fn; this platform has no umask.
func withUmask(_ int, fn func() error) error { return fn() }
