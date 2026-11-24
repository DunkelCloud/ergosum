//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecretEditInMemory: without -tmpdir, the file for the editor lies
// with mode 0600 in a new directory with mode 0700 on tmpfs or ramfs,
// below $XDG_RUNTIME_DIR if that is in memory, and nothing stays there.
func TestSecretEditInMemory(t *testing.T) {
	runtimeDir := ""
	for _, dir := range []string{"/dev/shm", "/run"} {
		if ram, _ := inRAM(dir); !ram {
			continue
		}
		if d, err := os.MkdirTemp(dir, "ergosum-test-"); err == nil {
			runtimeDir = d
			break
		}
	}
	if runtimeDir == "" {
		t.Skip("no directory on tmpfs or ramfs can be written here")
	}
	t.Cleanup(func() { os.RemoveAll(runtimeDir) })

	c := newEditCase(t, "old")
	editor := fakeEditorCommand(t, "report="+c.report, c.text(t, "text", "new\n"), "litter")
	r := c.d.run(t, "", []string{"EDITOR=" + editor, "XDG_RUNTIME_DIR=" + runtimeDir}, "secret", "edit", "restic", "-file", c.path)
	if r.code != 0 || strings.Contains(r.stderr, "warning") {
		t.Fatalf("edit: code %d, stderr %q", r.code, r.stderr)
	}
	got := c.reported(t)
	if dir := filepath.Dir(got.File); filepath.Dir(dir) != runtimeDir || !strings.HasPrefix(filepath.Base(dir), "ergosum-edit-") {
		t.Errorf("the file for the editor was %s, not in a directory of its own below %s", got.File, runtimeDir)
	}
	if got.FileMode != 0o600 || got.DirMode != 0o700 {
		t.Errorf("the file had mode %o in a directory with mode %o", got.FileMode, got.DirMode)
	}
	entries, err := os.ReadDir(runtimeDir)
	if err != nil || len(entries) != 0 {
		t.Errorf("edit left %d entries below %s (%v)", len(entries), runtimeDir, err)
	}
	if g := c.d.run(t, "", nil, "secret", "get", "-file", c.path); g.stdout != "new" {
		t.Errorf("get after edit: %q, %s", g.stdout, g.stderr)
	}
}

// TestSecretEditTmpdirWarning: -tmpdir is taken as it is; edit warns if
// the directory is on neither tmpfs nor ramfs, and only then.
func TestSecretEditTmpdirWarning(t *testing.T) {
	c := newEditCase(t, "old")
	ram, known := inRAM(c.tmp)
	if !known {
		t.Fatalf("the file system of %s cannot be read", c.tmp)
	}
	r := c.edit(t, []string{c.text(t, "text", "new\n")})
	if r.code != 0 {
		t.Fatalf("edit: code %d, stderr %q", r.code, r.stderr)
	}
	if warned := strings.Contains(r.stderr, "warning: -tmpdir "+c.tmp+" is on neither tmpfs nor ramfs"); warned == ram {
		t.Errorf("-tmpdir in memory: %t, warned: %t (%q)", ram, warned, r.stderr)
	}
	c.clean(t)
}
