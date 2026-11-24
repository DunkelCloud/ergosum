package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// editDir makes the private directory, mode 0700, that holds the secret
// for the editor: below tmpdir if one is given, taken as it is, else below
// the first directory in memory that can be written.
func editDir(tmpdir string) (string, error) {
	const pattern = "ergosum-edit-"
	if tmpdir != "" {
		dir, err := filepath.Abs(tmpdir)
		if err != nil {
			return "", err
		}
		if ram, known := inRAM(dir); known && !ram {
			fmt.Fprintf(os.Stderr, "ergosumd: warning: -tmpdir %s is on neither tmpfs nor ramfs; the secret may be written to a disk\n", dir)
		}
		return os.MkdirTemp(dir, pattern)
	}
	if runtime.GOOS != "linux" {
		return "", errors.New("edit finds a directory in memory only on Linux; name one with -tmpdir, such as a mounted RAM disk")
	}
	var failed []string
	for _, dir := range ramDirs() {
		private, err := os.MkdirTemp(dir, pattern)
		if err == nil {
			return private, nil
		}
		failed = append(failed, err.Error())
	}
	if len(failed) == 0 {
		failed = []string{"none of $XDG_RUNTIME_DIR, /run and /dev/shm is on tmpfs or ramfs"}
	}
	return "", fmt.Errorf("no directory in memory for the editor's file (%s); name one with -tmpdir", strings.Join(failed, "; "))
}
