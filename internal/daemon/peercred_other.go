//go:build !linux && !darwin

package daemon

import "net"

// peerUID is not available on this platform.
func peerUID(net.Conn) int { return -1 }
