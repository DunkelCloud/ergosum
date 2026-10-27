//go:build linux

package authority

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// bindToDevice pins a socket to an interface (SO_BINDTODEVICE), so that a
// callback cannot be rerouted through the overlay or an exit node.
func bindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.BindToDevice(int(fd), iface) //nolint:gosec // fd fits in int
		})
		if err != nil {
			return err
		}
		return serr
	}
}
