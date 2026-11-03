//go:build !linux

package daemon

// addressLifetimes is known on Linux only; elsewhere every address is of
// unknown lifetime.
func addressLifetimes() map[addrKey]addrLifetime { return nil }
