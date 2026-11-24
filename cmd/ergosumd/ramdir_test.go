package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestEditDir: -tmpdir is taken as it is, and the directory for the
// editor's file is a new one below it, with mode 0700. Without -tmpdir,
// only Linux has directories to look at.
func TestEditDir(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	if err := os.Mkdir("ram", 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tmpdir := range []string{tmp, "ram"} {
		dir, err := editDir(tmpdir)
		if err != nil {
			t.Fatal(err)
		}
		abs, _ := filepath.Abs(tmpdir)
		if filepath.Dir(dir) != abs || !strings.HasPrefix(filepath.Base(dir), "ergosum-edit-") {
			t.Errorf("-tmpdir %s: %s", tmpdir, dir)
		}
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700) {
			t.Errorf("-tmpdir %s: %v, mode %v", tmpdir, err, fi.Mode())
		}
		again, err := editDir(tmpdir)
		if err != nil || again == dir {
			t.Errorf("-tmpdir %s a second time: %s, %v", tmpdir, again, err)
		}
	}
	if dir, err := editDir(filepath.Join(tmp, "missing")); err == nil {
		t.Errorf("a -tmpdir that is not there: %s", dir)
	}
	if runtime.GOOS == "linux" {
		return
	}
	if dir, err := editDir(""); err == nil || !strings.Contains(err.Error(), "-tmpdir") {
		t.Errorf("without -tmpdir: %s, %v", dir, err)
	}
}
