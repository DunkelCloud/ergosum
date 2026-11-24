package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/DunkelCloud/ergosum/internal/secret"
)

// fakeEditorFlag makes the test binary the editor of the edit tests: it
// is started as "<binary> -fake-editor=OPS FILE", as edit starts $EDITOR.
const fakeEditorFlag = "-fake-editor="

// editorReport is what the fake editor was given.
type editorReport struct {
	Args     []string // its arguments after the flag
	File     string   // the last of them
	Text     string   // the content of the file
	FileMode uint32
	DirMode  uint32 // of the directory of the file
}

// fakeEditor runs ops, separated by commas, in order:
//
//	report=PATH   write an editorReport to PATH
//	text=PATH     put the content of PATH into the file
//	replace=PATH  the same in a new file renamed over the old one, as some
//	              editors save
//	litter        leave a file of its own next to the file
//	wait=PATH     wait until PATH exists
//	exit=N        end with exit code N
func fakeEditor(ops string, args []string) {
	fail := func(err error) {
		if err != nil {
			os.Stderr.WriteString("fake editor: " + err.Error() + "\n")
			os.Exit(99)
		}
	}
	file := args[len(args)-1]
	for _, op := range strings.Split(ops, ",") {
		name, arg, _ := strings.Cut(op, "=")
		switch name {
		case "report":
			text, err := os.ReadFile(file)
			fail(err)
			fi, err := os.Stat(file)
			fail(err)
			di, err := os.Stat(filepath.Dir(file))
			fail(err)
			data, err := json.Marshal(editorReport{
				Args: args, File: file, Text: string(text),
				FileMode: uint32(fi.Mode().Perm()), DirMode: uint32(di.Mode().Perm()),
			})
			fail(err)
			fail(os.WriteFile(arg+".tmp", data, 0o600))
			fail(os.Rename(arg+".tmp", arg))
		case "text":
			text, err := os.ReadFile(arg)
			fail(err)
			fail(os.WriteFile(file, text, 0o600))
		case "replace":
			text, err := os.ReadFile(arg)
			fail(err)
			fail(os.WriteFile(file+".new", text, 0o644))
			fail(os.Rename(file+".new", file))
		case "litter":
			fail(os.WriteFile(file+".swp", []byte("what the editor keeps of the text"), 0o600))
		case "wait":
			for start := time.Now(); ; time.Sleep(10 * time.Millisecond) {
				if _, err := os.Stat(arg); err == nil {
					break
				}
				if time.Since(start) > 30*time.Second {
					fail(errors.New("waited in vain for " + arg))
				}
			}
		case "exit":
			code, err := strconv.Atoi(arg)
			fail(err)
			os.Exit(code)
		default:
			fail(errors.New("unknown operation " + op))
		}
	}
}

// fakeEditorCommand is the command line that runs ops in the test binary
// as the editor, as $EDITOR takes it: words separated by spaces.
func fakeEditorCommand(t *testing.T, ops ...string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exe + " " + fakeEditorFlag + strings.Join(ops, ",")
	if len(strings.Fields(command)) != 2 {
		t.Skipf("a path of this test contains white space, which $EDITOR splits at: %s", command)
	}
	return command
}

// waitFor waits until the fake editor wrote path.
func waitFor(t *testing.T, path string) {
	t.Helper()
	for start := time.Now(); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Since(start) > 30*time.Second {
			t.Fatalf("the editor did not write %s", path)
		}
	}
}

// editCase is a part A of the secret "restic" at a fake daemon, and the
// directory that edit is given with -tmpdir.
type editCase struct {
	d      *fakeDaemon
	path   string // of part A
	tmp    string
	old    []byte // part A before the edit
	report string // where the fake editor reports
}

func newEditCase(t *testing.T, plain string, recipients ...string) *editCase {
	t.Helper()
	c := &editCase{d: newFakeDaemon(t), path: filepath.Join(t.TempDir(), "restic"), tmp: t.TempDir()}
	c.report = filepath.Join(t.TempDir(), "report")
	c.old = c.d.partA(t, "restic", 2, plain, recipients...)
	writeFile(t, c.path, c.old)
	return c
}

// text is the editor operation op (text or replace) with a file that holds
// content.
func (c *editCase) text(t *testing.T, op, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "text")
	writeFile(t, path, []byte(content))
	return op + "=" + path
}

// edit runs "secret edit restic" with a fake editor that reports and then
// runs ops.
func (c *editCase) edit(t *testing.T, ops []string, args ...string) outcome {
	t.Helper()
	editor := fakeEditorCommand(t, append([]string{"report=" + c.report}, ops...)...)
	args = append([]string{"secret", "edit", "restic", "-file", c.path, "-tmpdir", c.tmp}, args...)
	return c.d.run(t, "", []string{"EDITOR=" + editor}, args...)
}

// reported returns what the fake editor was given.
func (c *editCase) reported(t *testing.T) editorReport {
	t.Helper()
	var r editorReport
	if err := json.Unmarshal(readFile(t, c.report), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// clean fails t if edit left anything below the directory of -tmpdir.
func (c *editCase) clean(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(c.tmp)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("edit left %s behind", filepath.Join(c.tmp, e.Name()))
	}
}

// untouched fails t unless part A is byte for byte what it was, nothing is
// left next to it or below -tmpdir, and the daemon holds nothing new.
func (c *editCase) untouched(t *testing.T) {
	t.Helper()
	if !bytes.Equal(readFile(t, c.path), c.old) {
		t.Error("part A changed")
	}
	alone(t, c.path)
	c.clean(t)
	c.d.mu.Lock()
	held := len(c.d.held)
	c.d.mu.Unlock()
	if !c.d.holds(c.old) || held != 1 {
		t.Errorf("the daemon holds %d secrets, the old one: %t", held, c.d.holds(c.old))
	}
}

// TestSecretEdit: edit shows the secret with a newline after it in a file
// with mode 0600 in a new directory with mode 0700 below -tmpdir, and seals
// what the editor leaves there, less one newline, in place of part A.
// Nothing stays below -tmpdir, also not what the editor wrote next to the
// file.
func TestSecretEdit(t *testing.T) {
	for _, tc := range []struct {
		name, plain, shown string
		op, left, want     string
		litter             bool
	}{
		{name: "a line", plain: "old", shown: "old\n", op: "text", left: "new\n", want: "new"},
		{name: "lines", plain: "a=1\nb=2", shown: "a=1\nb=2\n", op: "text", left: "a=1\nb=3\nc=4\n", want: "a=1\nb=3\nc=4"},
		{name: "saved without a newline", plain: "old", shown: "old\n", op: "text", left: "new", want: "new"},
		{name: "saved with CRLF", plain: "old", shown: "old\n", op: "text", left: "new\r\n", want: "new"},
		{name: "a secret that ends with a newline", plain: "old\n", shown: "old\n\n", op: "text", left: "new\n\n", want: "new\n"},
		{name: "saved by renaming a new file", plain: "old", shown: "old\n", op: "replace", left: "new\n", want: "new"},
		{name: "the editor leaves a file of its own", plain: "old", shown: "old\n", op: "text", left: "new\n", want: "new", litter: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newEditCase(t, tc.plain)
			ops := []string{c.text(t, tc.op, tc.left)}
			if tc.litter {
				ops = append(ops, "litter")
			}
			r := c.edit(t, ops)
			if r.code != 0 || r.stdout != "" || !strings.Contains(r.stderr, "part A of restic replaced in "+c.path) {
				t.Fatalf("edit: code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
			}
			got := c.reported(t)
			dir := filepath.Dir(got.File)
			if got.Text != tc.shown || filepath.Base(got.File) != "restic" || filepath.Dir(dir) != c.tmp || len(got.Args) != 1 {
				t.Errorf("the editor was given %q with %q", got.Args, got.Text)
			}
			if runtime.GOOS != "windows" && (got.FileMode != 0o600 || got.DirMode != 0o700) {
				t.Errorf("the file had mode %o in a directory with mode %o", got.FileMode, got.DirMode)
			}
			c.clean(t)
			alone(t, c.path)
			now := readFile(t, c.path)
			s, err := secret.Parse(now)
			if err != nil {
				t.Fatal(err)
			}
			if s.Name != "restic" || s.Threshold != 2 || len(s.Pins) < s.Threshold {
				t.Errorf("part A after edit: name %s, threshold %d, %d pins", s.Name, s.Threshold, len(s.Pins))
			}
			if c.d.holds(c.old) || !c.d.holds(now) {
				t.Errorf("the daemon holds the old part A: %t, the new one: %t", c.d.holds(c.old), c.d.holds(now))
			}
			if g := c.d.run(t, "", nil, "secret", "get", "-file", c.path); g.code != 0 || g.stdout != tc.want {
				t.Errorf("get after edit: %q, code %d, %s", g.stdout, g.code, g.stderr)
			}
		})
	}
}

// TestSecretEditUnchanged: an editor that leaves the text as it was, also
// one that saves it again or drops the newline at its end, ends edit with
// exit code 0 and a note; part A stays byte for byte, and the daemon is not
// asked to seal.
func TestSecretEditUnchanged(t *testing.T) {
	for _, tc := range []struct{ name, plain, left string }{
		{"not saved", "old", ""},
		{"saved as it was", "old", "old\n"},
		{"saved without the newline", "old", "old"},
		{"a secret that ends with a newline", "old\n", "old\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newEditCase(t, tc.plain)
			var ops []string
			if tc.left != "" {
				ops = []string{c.text(t, "text", tc.left)}
			}
			r := c.edit(t, ops)
			if r.code != 0 || r.stdout != "" || !strings.Contains(r.stderr, "part A of restic is not replaced") {
				t.Fatalf("edit: code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
			}
			c.untouched(t)
			if c.d.asked("create") {
				t.Error("the daemon was asked to seal")
			}
		})
	}
}

// TestSecretEditRefused: whatever ends edit without a new secret leaves
// part A byte for byte as it was and nothing below -tmpdir.
func TestSecretEditRefused(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		recipients []string // of the recovery copy in part A
		left       string   // what the editor leaves
		ops        []string // what it does then
		env        []string
		prepare    func(d *fakeDaemon)
		opened     bool // the daemon was asked for the secret
		edited     bool // the editor ran
		want       string
	}{
		{name: "the editor fails", left: "new\n", ops: []string{"exit=3"}, opened: true, edited: true, want: "failed: exit status 3"},
		{name: "empty", left: "\n", opened: true, edited: true, want: "the new secret is empty"},
		{name: "nothing at all", left: "none", opened: true, edited: true, want: "the new secret is empty"},
		{name: "too long", left: strings.Repeat("x", secret.MaxSecret+1) + "\n", opened: true, edited: true, want: "longer than"},
		{name: "a recovery copy and no -recovery", recipients: []string{identity.Recipient().String()}, left: "new\n", want: "-recovery"},
		{name: "no such editor", env: []string{"VISUAL=" + filepath.Join(t.TempDir(), "no-editor")}, left: "new\n", want: "cannot be started"},
		{
			name: "the daemon cannot seal", left: "new\n", opened: true, edited: true, want: "1 instances can be pinned",
			prepare: func(d *fakeDaemon) { d.createErr = "1 instances can be pinned, the threshold is 2" },
		},
		{
			name: "the secret does not open", left: "new\n", want: "0 of the shares needed opened",
			prepare: func(d *fakeDaemon) { d.sealed = map[[32]byte][]byte{} },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newEditCase(t, "old", tc.recipients...)
			if tc.prepare != nil {
				c.d.mu.Lock()
				tc.prepare(c.d)
				c.d.mu.Unlock()
			}
			left := tc.left
			if left == "none" {
				left = ""
			}
			editor := fakeEditorCommand(t, append([]string{"report=" + c.report, c.text(t, "text", left)}, tc.ops...)...)
			env := append([]string{"EDITOR=" + editor}, tc.env...)
			r := c.d.run(t, "", env, "secret", "edit", "restic", "-file", c.path, "-tmpdir", c.tmp)
			if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, tc.want) || !strings.Contains(r.stderr, "part A is as it was") {
				t.Fatalf("edit: code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
			}
			c.untouched(t)
			c.d.mu.Lock()
			requests := strings.Join(c.d.requests, " ")
			c.d.mu.Unlock()
			if opened := strings.Contains(requests, "get"); opened != tc.opened && tc.name != "the secret does not open" {
				t.Errorf("the daemon was asked for the secret: %t (%s)", opened, requests)
			}
			if _, err := os.Stat(c.report); (err == nil) != tc.edited {
				t.Errorf("the editor ran: %t", err == nil)
			}
		})
	}
}

// TestSecretEditVisual: $VISUAL goes before $EDITOR, and its words after
// the first reach the editor as arguments before the file.
func TestSecretEditVisual(t *testing.T) {
	c := newEditCase(t, "old")
	visual := fakeEditorCommand(t, "report="+c.report, c.text(t, "text", "new\n")) + " -a +2"
	r := c.d.run(t, "", []string{"VISUAL=" + visual, "EDITOR=" + filepath.Join(t.TempDir(), "no-editor")},
		"secret", "edit", "restic", "-file", c.path, "-tmpdir", c.tmp)
	if r.code != 0 {
		t.Fatalf("edit: code %d, stderr %q", r.code, r.stderr)
	}
	if got := c.reported(t); len(got.Args) != 3 || got.Args[0] != "-a" || got.Args[1] != "+2" || got.Args[2] != got.File {
		t.Fatalf("the editor was given %q", got.Args)
	}
}

// TestSecretEditRecovery: with -recovery, the recovery copy of the new
// part A opens the edited secret.
func TestSecretEditRecovery(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recipient := identity.Recipient().String()
	c := newEditCase(t, "old", recipient)
	r := c.edit(t, []string{c.text(t, "text", "new\n")}, "-recovery", recipient)
	if r.code != 0 || !strings.Contains(r.stderr, "with a recovery copy") {
		t.Fatalf("edit: code %d, stderr %q", r.code, r.stderr)
	}
	s, err := secret.Parse(readFile(t, c.path))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := age.Decrypt(armor.NewReader(strings.NewReader(s.Recovery)), identity)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := io.ReadAll(opened); err != nil || string(plain) != "new" {
		t.Fatalf("the recovery copy opens %q, %v", plain, err)
	}
}

// TestSecretEditConflict: part A may change while the editor is open. If a
// get put a re-split part A of the same secret there, edit replaces it; if
// another command put another secret there, edit stops and leaves it.
func TestSecretEditConflict(t *testing.T) {
	t.Run("re-split", func(t *testing.T) {
		c := newEditCase(t, "old")
		resplit := c.d.partA(t, "restic", 2, "old")
		c.d.mu.Lock()
		c.d.onCreate = func() { writeFile(t, c.path, resplit) }
		c.d.mu.Unlock()
		if r := c.edit(t, []string{c.text(t, "text", "new\n")}); r.code != 0 {
			t.Fatalf("edit: code %d, stderr %q", r.code, r.stderr)
		}
		now := readFile(t, c.path)
		if c.d.holds(c.old) || c.d.holds(resplit) || !c.d.holds(now) {
			t.Errorf("the daemon holds the old part A: %t, the re-split one: %t, the new one: %t", c.d.holds(c.old), c.d.holds(resplit), c.d.holds(now))
		}
		if g := c.d.run(t, "", nil, "secret", "get", "-file", c.path); g.stdout != "new" {
			t.Errorf("get after edit: %q, %s", g.stdout, g.stderr)
		}
		c.clean(t)
	})
	t.Run("another secret", func(t *testing.T) {
		c := newEditCase(t, "old")
		other := c.d.partA(t, "restic", 2, "changed elsewhere")
		c.d.mu.Lock()
		c.d.onCreate = func() { writeFile(t, c.path, other) }
		c.d.mu.Unlock()
		r := c.edit(t, []string{c.text(t, "text", "new\n")})
		if r.code != 1 || !strings.Contains(r.stderr, "another command changed the secret meanwhile") {
			t.Fatalf("edit: code %d, stderr %q", r.code, r.stderr)
		}
		if !bytes.Equal(readFile(t, c.path), other) {
			t.Error("edit overwrote the secret that another command put there")
		}
		c.d.mu.Lock()
		held := len(c.d.held)
		c.d.mu.Unlock()
		if !c.d.holds(other) || held != 2 {
			t.Errorf("the daemon holds %d secrets, the other one: %t; the edited one should be forgotten", held, c.d.holds(other))
		}
		c.clean(t)
		alone(t, c.path)
	})
}

// TestEditorCommand: $VISUAL, else $EDITOR, split at white space; without
// both, vi, and an editor that is not there is named with what to set.
func TestEditorCommand(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Fields(exe)) != 1 {
		t.Skipf("the path of the test binary contains white space: %s", exe)
	}
	for _, tc := range []struct {
		visual, editor string
		want           []string
	}{
		{exe + "  -w", "nothing", []string{exe, "-w"}},
		{"", exe, []string{exe}},
		{"  ", exe + " -a -b", []string{exe, "-a", "-b"}},
	} {
		t.Setenv("VISUAL", tc.visual)
		t.Setenv("EDITOR", tc.editor)
		got, err := editorCommand()
		if err != nil || strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("VISUAL=%q EDITOR=%q: %q, %v; want %q", tc.visual, tc.editor, got, err, tc.want)
		}
	}
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	t.Setenv("PATH", t.TempDir())
	if _, err := editorCommand(); err == nil || !strings.Contains(err.Error(), "the editor vi cannot be started") || !strings.Contains(err.Error(), "VISUAL or EDITOR") {
		t.Errorf("no editor set and no vi: %v", err)
	}
}

// TestIsVim: vim and nvim get the flags by their name; vi only if it
// answers --version as Vim or Neovim do, since BusyBox and nvi would refuse
// them.
func TestIsVim(t *testing.T) {
	asked := ""
	version := func(answer string) func(string) string {
		return func(editor string) string {
			asked = editor
			return answer
		}
	}
	for _, tc := range []struct {
		editor, version string
		want            bool
	}{
		{"/usr/bin/vim", "", true},
		{"nvim", "", true},
		{"/usr/bin/vi", "VIM - Vi IMproved 9.1 (2024 Jan 02, compiled Nov 11 2025 10:05:21)\n", true},
		{"/usr/bin/vi", "NVIM v0.10.4\nBuild type: Release\n", true},
		{"/bin/vi", "vi: unrecognized option: -\nBusyBox v1.37.0 (2025-01-17 18:12:01 UTC) multi-call binary.\n\nUsage: vi [-c CMD] [-R] [-H] [FILE]...\n", false},
		{"/usr/bin/vi", "", false},
		{"/usr/bin/nano", "VIM - Vi IMproved", false},
		{"/usr/bin/view", "VIM - Vi IMproved", false},
		{"/usr/bin/code", "", false},
	} {
		asked = ""
		if got := isVim(tc.editor, version(tc.version)); got != tc.want {
			t.Errorf("%s: %t, want %t", tc.editor, got, tc.want)
		}
		if isVi := filepath.Base(tc.editor) == "vi"; (asked != "") != isVi {
			t.Errorf("%s: asked for its version: %t", tc.editor, asked != "")
		}
	}
}

// editResult is what editing.edit returned.
type editResult struct {
	text    []byte
	changed bool
	err     error
}

// startEdit runs edit with a fake editor that reports to report and then
// waits for the file release before it leaves "new" as the text.
func startEdit(t *testing.T, e *editing, report, release string) <-chan editResult {
	t.Helper()
	text := filepath.Join(t.TempDir(), "text")
	writeFile(t, text, []byte("new\n"))
	editor := strings.Fields(fakeEditorCommand(t, "report="+report, "wait="+release, "text="+text))
	done := make(chan editResult, 1)
	go func() {
		text, changed, err := e.edit(editor, "restic", []byte("old"))
		done <- editResult{text, changed, err}
	}()
	return done
}

func await(t *testing.T, done <-chan editResult) editResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(30 * time.Second):
		t.Fatal("edit did not return")
		return editResult{}
	}
}

// TestEditingSignals: SIGTERM and SIGHUP end the editor and the edit, and
// close removes the directory with the file. An interrupt is left to the
// editor while it runs, and ends the edit before it runs.
func TestEditingSignals(t *testing.T) {
	private := func(t *testing.T) string {
		t.Helper()
		dir, err := os.MkdirTemp(t.TempDir(), "ergosum-edit-")
		if err != nil {
			t.Fatal(err)
		}
		return dir
	}
	gone := func(t *testing.T, dir string) {
		t.Helper()
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the directory of the file is still there: %v", err)
		}
	}
	for _, s := range []os.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(s.String(), func(t *testing.T) {
			dir, signals := private(t), make(chan os.Signal)
			e := startEditing(dir, signals)
			report := filepath.Join(t.TempDir(), "report")
			done := startEdit(t, e, report, filepath.Join(t.TempDir(), "never"))
			waitFor(t, report)
			signals <- s
			if r := await(t, done); r.err == nil || !strings.Contains(r.err.Error(), "ended by a signal ("+s.String()+")") {
				t.Fatalf("edit after %v: %q, %v", s, r.text, r.err)
			}
			if _, err := os.Stat(filepath.Join(dir, "restic")); err != nil {
				t.Errorf("the file before close: %v", err)
			}
			e.close()
			e.close()
			gone(t, dir)
		})
	}
	t.Run("interrupt while the editor runs", func(t *testing.T) {
		dir, signals := private(t), make(chan os.Signal)
		e := startEditing(dir, signals)
		report, release := filepath.Join(t.TempDir(), "report"), filepath.Join(t.TempDir(), "release")
		done := startEdit(t, e, report, release)
		waitFor(t, report)
		signals <- os.Interrupt
		writeFile(t, release, nil)
		if r := await(t, done); r.err != nil || !r.changed || string(r.text) != "new" {
			t.Fatalf("edit after an interrupt: %q, changed %t, %v", r.text, r.changed, r.err)
		}
		e.close()
		gone(t, dir)
	})
	t.Run("interrupt before the editor runs", func(t *testing.T) {
		dir, signals := private(t), make(chan os.Signal)
		e := startEditing(dir, signals)
		signals <- os.Interrupt
		<-e.ctx.Done()
		report := filepath.Join(t.TempDir(), "report")
		if r := await(t, startEdit(t, e, report, filepath.Join(t.TempDir(), "never"))); r.err == nil {
			t.Fatal("edit ran after an interrupt")
		}
		if _, err := os.Stat(report); err == nil {
			t.Error("the editor ran after an interrupt")
		}
		e.close()
		gone(t, dir)
	})
}

// TestWipe: the files of the directory are overwritten before they are
// removed with it.
func TestWipe(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "restic")
	writeFile(t, file, bytes.Repeat([]byte("secret"), 20000))
	writeFile(t, filepath.Join(dir, "sub", "restic.swp"), []byte("secret"))
	overwrite(file)
	if data := readFile(t, file); len(data) != 120000 || !bytes.Equal(data, make([]byte, 120000)) {
		t.Errorf("after overwrite, the file holds %d bytes, not 120000 zeros", len(data))
	}
	if err := wipe(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("after wipe: %v", err)
	}
}
