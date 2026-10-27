//go:build !linux

package authority

import (
	"errors"
	"syscall"
)

func bindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(string, string, syscall.RawConn) error {
		return errors.New("binding to an interface is only supported on Linux")
	}
}
