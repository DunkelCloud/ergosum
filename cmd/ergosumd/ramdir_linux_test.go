//go:build linux

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestRAMDirs: only directories on tmpfs or ramfs count, in the order
// $XDG_RUNTIME_DIR, /run, /dev/shm; one on another file system, a relative
// one and a missing one do not.
func TestRAMDirs(t *testing.T) {
	if ram, known := inRAM("/proc"); ram || !known {
		t.Fatalf("/proc: in memory %t, known %t", ram, known)
	}
	if ram, known := inRAM("/nonexistent/dir"); ram || known {
		t.Fatalf("a missing directory: in memory %t, known %t", ram, known)
	}
	var mounted []string
	for _, dir := range []string{"/run", "/dev/shm"} {
		if ram, _ := inRAM(dir); ram {
			mounted = append(mounted, dir)
		}
	}
	if len(mounted) == 0 {
		t.Skip("neither /run nor /dev/shm is on tmpfs or ramfs here")
	}
	for _, other := range []string{"", "/proc", "run", "/nonexistent/dir"} {
		t.Setenv("XDG_RUNTIME_DIR", other)
		if got := ramDirs(); !slices.Equal(got, mounted) {
			t.Errorf("XDG_RUNTIME_DIR=%q: %q, want %q", other, got, mounted)
		}
	}
	// A runtime directory in memory comes first.
	for _, dir := range mounted {
		runtimeDir, err := os.MkdirTemp(dir, "ergosum-test-")
		if err != nil {
			continue // not writable for this user
		}
		t.Cleanup(func() { os.RemoveAll(runtimeDir) })
		t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
		if got, want := ramDirs(), append([]string{runtimeDir}, mounted...); !slices.Equal(got, want) {
			t.Errorf("XDG_RUNTIME_DIR in memory: %q, want %q", got, want)
		}
		return
	}
	t.Log("no directory in memory is writable here: a runtime directory in memory was not tried")
}

// TestEditDirInMemory: without -tmpdir, the directory for the editor's
// file is a new one with mode 0700 below the first directory in memory
// that can be written.
func TestEditDirInMemory(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	dir, err := editDir("")
	if err != nil {
		for _, parent := range ramDirs() {
			if probe, perr := os.MkdirTemp(parent, "ergosum-test-"); perr == nil {
				os.Remove(probe)
				t.Fatalf("%s can be written, but: %v", parent, err)
			}
		}
		t.Skipf("no directory in memory can be written here: %v", err)
	}
	t.Cleanup(func() { os.Remove(dir) })
	if ram, known := inRAM(dir); !ram || !known {
		t.Errorf("%s: in memory %t, known %t", dir, ram, known)
	}
	if !slices.Contains(ramDirs(), filepath.Dir(dir)) {
		t.Errorf("%s is below none of %q", dir, ramDirs())
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("%s: %v, mode %v", dir, err, fi.Mode())
	}
}
