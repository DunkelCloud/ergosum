package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/DunkelCloud/ergosum/internal/cli"
	"github.com/DunkelCloud/ergosum/internal/secret"
)

func secretEdit(args []string) error {
	f := newSecretFlags("edit", changeFileUsage, true)
	tmpdir := f.fs.String("tmpdir", "", "put the file for the editor below `DIR`, taken as it is, instead of a "+
		"directory in memory that edit finds itself: for a system where it finds none, such as macOS, with a RAM "+
		"disk mounted at DIR. On Linux, edit warns if DIR is on neither tmpfs nor ramfs.")
	var rec recipients
	f.fs.Var(&rec, "recovery", changeRecoveryUsage)
	cli.Usage(f.fs, "ergosumd secret edit NAME [-recovery RECIPIENT]... [-file PATH] [-tmpdir DIR]",
		`Opens the secret in an editor and seals what the editor leaves in place of
it, as replace does: same name and threshold, the file of part A replaced
in one step with its owner and mode.
The text lies in memory only: in a file with mode 0600 in a new directory
with mode 0700 below $XDG_RUNTIME_DIR, /run or /dev/shm, the first of them
that is on tmpfs or ramfs. Where none is, as on macOS, edit stops before
it opens the secret, unless -tmpdir names a directory. When the editor
ends, the file is overwritten and removed with its directory. SIGTERM and
SIGHUP end the editor and do the same; an interrupt (Ctrl-C) is left to
the editor while it runs.
The editor is $VISUAL, else $EDITOR, else vi; words after the first are
its arguments. Vim and Neovim, named vi, vim or nvim, are started with
  -n -i NONE -c 'set nobackup nowritebackup noundofile'
and so keep no swap, backup, undo or history file. With any other editor,
files it writes outside that directory are yours to prevent.
The file ends with one newline more than the secret, and one is removed
after the editor, as create removes it. edit changes nothing if the editor
fails, or leaves the text empty or as it was (then with exit code 0). It
stops if another command changed the secret meanwhile; a part A that a get
re-split meanwhile is replaced. If sealing fails, the changes are lost:
the text is kept nowhere.
A part A with a recovery copy needs -recovery, as for replace. Memory may
be swapped out, and a copy of the old part A still opens the old secret.
  ergosumd secret edit restic -recovery 'age1...'
`, nameArg)
	name, path, err := f.parse(args)
	if err != nil {
		return err
	}
	old, s, err := f.existing(name, path, rec)
	if err != nil {
		return err
	}
	editor, err := editorCommand()
	if err != nil {
		return asItWas(err)
	}
	e, err := newEditing(*tmpdir)
	if err != nil {
		return asItWas(err)
	}
	defer e.close()
	was, old, err := f.open(e.ctx, s.Name, path, old)
	if err != nil {
		return asItWas(err)
	}
	text, changed, err := e.edit(editor, s.Name, was)
	e.close()
	if err != nil {
		return asItWas(err)
	}
	if !changed {
		fmt.Fprintf(os.Stderr, "ergosumd: the editor left the secret as it was; part A of %s is not replaced\n", s.Name)
		return nil
	}
	return f.reseal(path, old, s, text, was, rec)
}

// vimFlags keep Vim and Neovim from writing what they show anywhere else:
// no swap file, no viminfo or shada file with registers and history, no
// backup and no undo file.
var vimFlags = []string{"-n", "-i", "NONE", "-c", "set nobackup nowritebackup noundofile"}

// editorCommand returns the command line of the editor, without the file:
// $VISUAL, else $EDITOR, split at white space, else vi.
func editorCommand() ([]string, error) {
	argv := []string{"vi"}
	for _, v := range []string{"VISUAL", "EDITOR"} {
		if words := strings.Fields(os.Getenv(v)); len(words) > 0 {
			argv = words
			break
		}
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, fmt.Errorf("the editor %s cannot be started (%w); name one in VISUAL or EDITOR", argv[0], err)
	}
	argv[0] = path
	if isVim(path, editorVersion) {
		argv = append(argv, vimFlags...)
	}
	return argv, nil
}

// isVim reports whether the editor takes vimFlags: vim and nvim by their
// name. vi is Vim on many systems and another editor on others (BusyBox,
// nvi), which would refuse the flags; there, what it answers to --version
// tells.
func isVim(editor string, version func(string) string) bool {
	switch strings.TrimSuffix(strings.ToLower(filepath.Base(editor)), ".exe") {
	case "vim", "nvim":
		return true
	case "vi":
		v := version(editor)
		return strings.Contains(v, "VIM - Vi IMproved") || strings.Contains(v, "NVIM")
	}
	return false
}

// editorVersion returns what the editor writes for --version, as far as it
// does so within five seconds and without a terminal.
func editorVersion(editor string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, editor, "--version") //nolint:gosec // the caller's editor
	cmd.WaitDelay = time.Second
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// editing is the time in which the secret lies in a file for the editor:
// the private directory of that file, and a context that ends with the
// first signal that ends the command.
type editing struct {
	dir     string
	ctx     context.Context
	cancel  context.CancelCauseFunc
	signals chan os.Signal

	mu     sync.Mutex
	editor bool      // the editor runs: an interrupt is its own to handle
	signal os.Signal // the signal that ended ctx
}

// newEditing makes the private directory and watches for the signals from
// then on, so that no signal leaves the directory behind.
func newEditing(tmpdir string) (*editing, error) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	dir, err := editDir(tmpdir)
	if err != nil {
		signal.Stop(signals)
		return nil, err
	}
	return startEditing(dir, signals), nil
}

func startEditing(dir string, signals chan os.Signal) *editing {
	e := &editing{dir: dir, signals: signals}
	e.ctx, e.cancel = context.WithCancelCause(context.Background())
	go e.watch()
	return e
}

// watch ends ctx with the first signal that is the command's to obey. The
// terminal sends an interrupt to the editor as well, and an editor may have
// its own use for it: while one runs, the command leaves it to the editor.
func (e *editing) watch() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case s := <-e.signals:
			e.mu.Lock()
			own := e.editor && s == os.Interrupt
			if !own {
				e.signal = s
			}
			e.mu.Unlock()
			if !own {
				e.cancel(fmt.Errorf("ended by a signal (%v)", s))
				return
			}
		}
	}
}

// close overwrites and removes the directory with all it holds and stops
// watching for signals. It may be called more than once.
func (e *editing) close() {
	signal.Stop(e.signals)
	e.cancel(nil)
	if e.dir == "" {
		return
	}
	if err := wipe(e.dir); err != nil {
		fmt.Fprintf(os.Stderr, "ergosumd: %s cannot be removed and may still hold the secret: %v\n", e.dir, err)
	}
	e.dir = ""
}

// edit writes text and a newline to a new file in the private directory,
// runs the editor on it and returns what the editor left there, less one
// trailing newline. changed is false if that is text again.
func (e *editing) edit(editor []string, name string, text []byte) (edited []byte, changed bool, err error) {
	if err := context.Cause(e.ctx); err != nil {
		return nil, false, err
	}
	file := filepath.Join(e.dir, name)
	shown := append(bytes.Clone(text), '\n')
	out, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // in the private directory
	if err != nil {
		return nil, false, err
	}
	_, err = out.Write(shown)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, false, err
	}
	if err := e.run(append(slices.Clone(editor), file)); err != nil {
		return nil, false, err
	}
	in, err := os.Open(file) //nolint:gosec // in the private directory
	if err != nil {
		return nil, false, fmt.Errorf("the editor left no file: %w", err)
	}
	left, err := io.ReadAll(io.LimitReader(in, secret.MaxSecret+3))
	_ = in.Close()
	if err != nil {
		return nil, false, err
	}
	if bytes.Equal(left, shown) {
		return nil, false, nil
	}
	edited = trimNewline(left)
	return edited, !bytes.Equal(edited, text), nil
}

// run runs the editor on the terminal of the command and waits for it. A
// signal that ends the command goes to the editor as well; an editor that
// then runs on for five seconds is killed.
func (e *editing) run(argv []string) error {
	cmd := exec.CommandContext(e.ctx, argv[0], argv[1:]...) //nolint:gosec // the caller's editor
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Cancel = func() error {
		e.mu.Lock()
		s := e.signal
		e.mu.Unlock()
		if s == nil || cmd.Process.Signal(s) != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 5 * time.Second
	e.setEditor(true)
	err := cmd.Run()
	e.setEditor(false)
	if cause := context.Cause(e.ctx); cause != nil {
		return cause
	}
	if err != nil {
		return fmt.Errorf("the editor %s failed: %w", argv[0], err)
	}
	return nil
}

func (e *editing) setEditor(running bool) {
	e.mu.Lock()
	e.editor = running
	e.mu.Unlock()
}

// wipe overwrites every file below dir with zeros and removes dir with all
// it holds: the file of the secret and what the editor wrote next to it.
func wipe(dir string) error {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			overwrite(path)
		}
		return nil
	})
	return os.RemoveAll(dir)
}

// overwrite fills the file with zeros, as far as it can be written.
func overwrite(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // in the private directory
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	zeros := make([]byte, 32<<10)
	for left := fi.Size(); left > 0; left -= int64(len(zeros)) {
		if _, err := f.Write(zeros[:min(left, int64(len(zeros)))]); err != nil {
			return
		}
	}
	_ = f.Sync()
}
