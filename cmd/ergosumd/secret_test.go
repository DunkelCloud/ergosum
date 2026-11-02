package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecretPath: NAME alone means part A in the secrets directory; a
// relative -file is taken from the working directory and returned absolute,
// the form that get needs from anywhere else.
func TestSecretPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	abs := filepath.Join(t.TempDir(), "restic")
	for _, tc := range []struct {
		args       []string
		name, path string
	}{
		{[]string{"restic"}, "restic", filepath.Join(defaultSecretDir, "restic")},
		{[]string{"restic", "-file", "restic"}, "restic", filepath.Join(dir, "restic")},
		{[]string{"-file", "sub/restic", "restic"}, "restic", filepath.Join(dir, "sub", "restic")},
		{[]string{"-file", abs}, "", abs},
	} {
		name, path, err := newSecretFlags("get").parse(tc.args)
		if err != nil || name != tc.name || path != tc.path {
			t.Errorf("%q: %q, %q, %v; want %q, %q", tc.args, name, path, err, tc.name, tc.path)
		}
	}
}

// TestSecretMissingPartA: NAME alone looks only in the secrets directory
// and, when part A is not there, points to -file; a missing -file keeps the
// plain error.
func TestSecretMissingPartA(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "restic")

	f := newSecretFlags("get")
	if _, _, err := f.parse([]string{"restic"}); err != nil {
		t.Fatal(err)
	}
	_, err := f.readPartA("restic", missing)
	if err == nil || !strings.Contains(err.Error(), filepath.Dir(missing)) || !strings.Contains(err.Error(), "give its -file") {
		t.Fatalf("NAME alone: %v", err)
	}

	f = newSecretFlags("get")
	if _, _, err := f.parse([]string{"restic", "-file", missing}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.readPartA("restic", missing); !errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "-file") {
		t.Fatalf("with -file: %v", err)
	}
}
