//go:build unix

package authority

import "syscall"

// withUmask runs fn with the process umask set to mask, so that files and
// sockets fn creates never exist with wider permissions.
func withUmask(mask int, fn func() error) error {
	old := syscall.Umask(mask)
	defer syscall.Umask(old)
	return fn()
}
