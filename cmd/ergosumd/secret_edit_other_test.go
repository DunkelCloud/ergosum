//go:build !linux

package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// TestSecretEditNeedsTmpdir: where edit finds no directory in memory, it
// stops without -tmpdir before it asks the daemon for the secret and
// before the editor runs.
func TestSecretEditNeedsTmpdir(t *testing.T) {
	c := newEditCase(t, "old")
	editor := fakeEditorCommand(t, "report="+c.report, c.text(t, "text", "new\n"))
	r := c.d.run(t, "", []string{"EDITOR=" + editor}, "secret", "edit", "restic", "-file", c.path)
	if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, "-tmpdir") || !strings.Contains(r.stderr, "part A is as it was") {
		t.Fatalf("edit: code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
	c.untouched(t)
	if c.d.asked("get") {
		t.Error("the daemon was asked for the secret")
	}
	if _, err := os.Stat(c.report); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the editor ran: %v", err)
	}
}
