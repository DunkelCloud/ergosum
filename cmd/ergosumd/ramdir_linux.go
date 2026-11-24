//go:build linux

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ramDirs returns the directories that hold their files in memory, in the
// order to try them: $XDG_RUNTIME_DIR, /run and /dev/shm, as far as the
// kernel names tmpfs or ramfs as their file system.
func ramDirs() []string {
	var dirs []string
	for _, dir := range []string{os.Getenv("XDG_RUNTIME_DIR"), "/run", "/dev/shm"} {
		if !filepath.IsAbs(dir) {
			continue
		}
		if ram, _ := inRAM(dir); ram {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// inRAM reports whether dir lies on tmpfs or ramfs; known is false if the
// file system of dir cannot be read.
func inRAM(dir string) (ram, known bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false, false
	}
	// The width and sign of Type differ between architectures.
	fs := uint32(st.Type) //nolint:gosec // a magic number of 32 bits
	return fs == unix.TMPFS_MAGIC || fs == unix.RAMFS_MAGIC, true
}
