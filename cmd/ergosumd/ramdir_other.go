//go:build !linux

package main

// ramDirs returns no directory: this platform mounts no file system that
// is known to hold its files in memory.
func ramDirs() []string { return nil }

// inRAM cannot tell on this platform.
func inRAM(string) (ram, known bool) { return false, false }
