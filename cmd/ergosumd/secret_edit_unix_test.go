//go:build unix

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/DunkelCloud/ergosum/internal/cli/clitest"
)

// TestSecretEditSignal: SIGTERM and SIGHUP, sent to the command while the
// editor is open, end the editor and the command; part A stays as it was,
// and nothing stays below -tmpdir. An interrupt as the terminal sends it,
// to the command and the editor alike, is left to the editor: this one
// ends on it, and the command cleans up after it.
func TestSecretEditSignal(t *testing.T) {
	for _, tc := range []struct {
		name string
		send func(pid int) error
		want string
	}{
		{"SIGTERM", func(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }, "ended by a signal (terminated)"},
		{"SIGHUP", func(pid int) error { return syscall.Kill(pid, syscall.SIGHUP) }, "ended by a signal (hangup)"},
		{"interrupt from the terminal", func(pid int) error { return syscall.Kill(-pid, syscall.SIGINT) }, "failed: signal: interrupt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newEditCase(t, "old")
			editor := fakeEditorCommand(t, "report="+c.report, "wait="+filepath.Join(t.TempDir(), "never"), c.text(t, "text", "new\n"))
			cmd := clitest.Command(t, "secret", "edit", "restic", "-file", c.path, "-tmpdir", c.tmp, "-socket", c.d.socket)
			cmd.Env = append(cmd.Env, "VISUAL=", "EDITOR="+editor)
			// A process group of its own, as a shell gives a command.
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waitFor(t, c.report)
			if err := tc.send(cmd.Process.Pid); err != nil {
				t.Fatal(err)
			}
			err := cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("edit after the signal: %v, stderr %q", err, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) || !strings.Contains(stderr.String(), "part A is as it was") {
				t.Errorf("stderr %q", stderr.String())
			}
			c.untouched(t)
			if c.d.asked("create") {
				t.Error("the daemon was asked to seal")
			}
		})
	}
}

// TestSecretChangeNeedsDirectory: replace and edit write the new part A
// next to the old one. In a directory that the caller cannot write, they
// stop before a secret is sealed, opened or edited.
func TestSecretChangeNeedsDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes any directory")
	}
	c := newEditCase(t, "old")
	dir := filepath.Dir(c.path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	for _, r := range []outcome{
		c.d.run(t, "new\n", nil, "secret", "replace", "restic", "-file", c.path),
		c.edit(t, []string{c.text(t, "text", "new\n")}),
	} {
		if r.code != 1 || !strings.Contains(r.stderr, "part A cannot be replaced") || !strings.Contains(r.stderr, "part A is as it was") {
			t.Errorf("code %d, stderr %q", r.code, r.stderr)
		}
	}
	c.untouched(t)
	if _, err := os.Stat(c.report); err == nil {
		t.Error("the editor ran")
	}
	c.d.mu.Lock()
	requests := len(c.d.requests)
	c.d.mu.Unlock()
	if requests != 0 {
		t.Errorf("the daemon got %d requests", requests)
	}
}
