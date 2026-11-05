package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/DunkelCloud/ergosum/internal/cli"
	"github.com/DunkelCloud/ergosum/internal/daemon"
	"github.com/DunkelCloud/ergosum/internal/secret"
)

// defaultSecretDir holds part A of each secret, by name.
const defaultSecretDir = "/etc/ergosum/secrets" //nolint:gosec // a directory, not a credential

// secretCmd implements "ergosumd secret create|get|info" (ADR 0004).
func secretCmd(args []string) error {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		return secretCreate(args[1:])
	case "get":
		return secretGet(args[1:])
	case "info":
		return secretInfo(args[1:])
	default:
		usage()
		os.Exit(2)
	}
	return nil
}

// recipients collects repeated -recovery flags.
type recipients []string

func (r *recipients) String() string     { return strings.Join(*r, ", ") }
func (r *recipients) Set(s string) error { *r = append(*r, s); return nil }

// secretFlags are the flags of the secret commands: -file for all, -config
// and -socket for those that ask the daemon.
type secretFlags struct {
	fs     *flag.FlagSet
	config *string
	socket *string
	file   *string
}

// nameArg is the NAME of every secret command.
var nameArg = cli.Arg{Name: "NAME", Text: "the secret's name: lower-case letters, digits and hyphens, at most 63 " +
	"characters. Part A lies at " + defaultSecretDir + "/NAME unless -file says otherwise."}

func newSecretFlags(name, fileUsage string, daemonFlags bool) *secretFlags {
	fs := flag.NewFlagSet("secret "+name, flag.ExitOnError)
	f := &secretFlags{fs: fs, config: new(string), socket: new(string)}
	f.file = fs.String("file", "", fileUsage)
	if daemonFlags {
		f.config = fs.String("config", defaultConfig, "read secret_socket, the daemon's socket, from the daemon configuration `FILE`")
		f.socket = fs.String("socket", "", "ask the daemon on the socket `PATH`, instead of secret_socket from the "+
			"configuration; without either, "+daemon.SecretSocketDefault())
	}
	return f
}

// readFileUsage is -file of the commands that read part A.
const readFileUsage = "read part A from `PATH` instead of " + defaultSecretDir + "/NAME: needed for a part A that " +
	"create wrote elsewhere. A relative PATH is taken from the working directory. With -file, NAME may be left out."

// parse takes NAME before or after the flags and returns it with the path
// of part A. Without -file a NAME is required. A relative -file is taken
// from the working directory and returned absolute, the form that get needs
// from anywhere else.
func (f *secretFlags) parse(args []string) (name, path string, err error) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	_ = f.fs.Parse(args)
	if f.fs.NArg() > 0 && name == "" {
		name = f.fs.Arg(0)
	} else if f.fs.NArg() > 0 {
		return "", "", fmt.Errorf("unexpected argument %q", f.fs.Arg(0))
	}
	switch {
	case *f.file != "":
		path, err = filepath.Abs(*f.file)
		return name, path, err
	case name == "":
		return "", "", errors.New("name a secret, or give -file")
	case !secret.ValidName(name):
		return "", "", fmt.Errorf("bad name %q: lower-case letters, digits and hyphens, at most 63 characters", name)
	}
	return name, filepath.Join(defaultSecretDir, name), nil
}

// readPartA reads part A from path. NAME alone finds part A only in the
// secrets directory: one that create wrote elsewhere needs its -file.
func (f *secretFlags) readPartA(name, path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if *f.file == "" && errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no part A of %s in %s; for one that create wrote elsewhere, give its -file", name, filepath.Dir(path))
	}
	return data, err
}

// socketPath is -socket, else the configured socket, else the default.
// The caller may not be allowed to read the configuration.
func (f *secretFlags) socketPath() string {
	if *f.socket != "" {
		return *f.socket
	}
	if cfg, err := daemon.LoadConfig(*f.config); err == nil {
		return cfg.SecretSocket
	}
	return daemon.SecretSocketDefault()
}

func secretCreate(args []string) error {
	f := newSecretFlags("create", "write part A to `PATH` instead of "+defaultSecretDir+"/NAME. A relative PATH is "+
		"taken from the working directory; create names it absolute. get and info then need the same -file.", true)
	threshold := f.fs.Int("threshold", 0, "the number `K` of pinned instances that must release their shares "+
		"to open the secret: required, 1 to 16. With 1, the exchange key of one instance and a copy of part A "+
		"open the secret without any check; 2 or more keep it closed while one instance is lost or broken into.")
	raw := f.fs.Bool("raw", false, "keep the input as it is; without -raw, one trailing newline (LF or CRLF), "+
		"as echo or an editor leaves it, is removed")
	var rec recipients
	f.fs.Var(&rec, "recovery", "also seal a recovery copy of the secret to `RECIPIENT`: an age X25519 public "+
		"key (age1...) or an ssh-ed25519 public key line (\"ssh-ed25519 AAAA... comment\", quoted as one "+
		"argument). The copy lies in part A as the member recovery and opens with the stock age tool and the "+
		"matching private key (age -d -i KEY), without ergosum and without any instance. Repeat -recovery "+
		"for more recipients; each one opens the copy alone. Without it there is no way back once fewer than "+
		"K pinned instances can release their shares.")
	cli.Usage(f.fs, "ergosumd secret create NAME -threshold K [-recovery RECIPIENT]... [-raw] [-file PATH]",
		`Seals a secret read from stdin, at most 64 KiB, into part A, a file that may
lie in backups and repositories: it opens only on this machine, after the
machine has passed the checks of its binding at K authority instances.
create pins a share to every instance of the authority list that hands out
a release key for the machine, at most 16, and fails with fewer than K,
naming the instances that did not answer and why. It writes part A with
mode 0600 and never overwrites one. Run it as root, or as a user that may
use secret_socket:
  printf '%s\n' "$PASSWORD" | ergosumd secret create restic -threshold 2 \
    -recovery 'age1...' -recovery 'ssh-ed25519 AAAA... admin@example.com'
`, nameArg)
	name, path, err := f.parse(args)
	if err != nil {
		return err
	}
	if !secret.ValidName(name) {
		return errors.New("create needs a NAME (lower-case letters, digits and hyphens)")
	}
	if *threshold < 1 {
		return errors.New("-threshold is required")
	}
	if _, err := os.Lstat(path); err == nil { //nolint:gosec // operator-supplied path
		return fmt.Errorf("%s exists; refusing to overwrite part A", path)
	}
	plain, err := io.ReadAll(io.LimitReader(os.Stdin, secret.MaxSecret+3))
	if err != nil {
		return err
	}
	if !*raw {
		// One trailing LF or CRLF, as an editor or echo leaves it.
		if bytes.HasSuffix(plain, []byte("\r\n")) {
			plain = plain[:len(plain)-2]
		} else {
			plain = bytes.TrimSuffix(plain, []byte("\n"))
		}
	}
	if len(plain) > secret.MaxSecret {
		return fmt.Errorf("the secret is longer than %d bytes", secret.MaxSecret)
	}
	recovery, err := secret.Recovery(plain, rec)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	resp, err := daemon.CallSecret(ctx, f.socketPath(), daemon.SecretRequest{
		Op: "create", Name: name, Threshold: *threshold, Secret: plain, Recovery: recovery,
	})
	if err != nil {
		return err
	}
	inDir := path == filepath.Join(defaultSecretDir, name)
	if inDir {
		if err := os.MkdirAll(defaultSecretDir, 0o700); err != nil {
			return err
		}
	}
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-supplied path
	if err != nil {
		return err
	}
	if _, err := out.Write(resp.PartA); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	s, err := secret.Parse(resp.PartA)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "part A of %s written to %s: threshold %d of %d pinned instances\n", name, path, s.Threshold, len(s.Pins))
	if !inDir {
		fmt.Fprintf(os.Stderr, "not in %s: get and info find it only with -file %s\n", defaultSecretDir, path)
	}
	return nil
}

// secretGet writes the secret to stdout: the bytes as stored, nothing
// else. On any failure stdout stays empty.
func secretGet(args []string) error {
	f := newSecretFlags("get", readFileUsage, true)
	cli.Usage(f.fs, "ergosumd secret get NAME [-file PATH]", `Opens the secret and writes it to stdout as stored, without a newline, and
nothing else; on any failure stdout stays empty and the exit code is 1. It
fits as a password command:
  RESTIC_PASSWORD_COMMAND='ergosumd secret get restic' restic snapshots
Who may read part A and use secret_socket may open the secret. The daemon
answers from memory while it holds the secret open; after the daemon
starts, the first get needs K of the pinned instances. If the authority
list has changed, get replaces part A with the re-split one and says so on
stderr.
`, nameArg)
	name, path, err := f.parse(args)
	if err != nil {
		return err
	}
	partA, err := f.readPartA(name, path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	resp, err := daemon.CallSecret(ctx, f.socketPath(), daemon.SecretRequest{Op: "get", PartA: partA})
	if err != nil {
		return err
	}
	if resp.PartA != nil {
		if name == "" {
			name = path
		}
		if err := replaceFile(path, resp.PartA); err != nil {
			fmt.Fprintf(os.Stderr, "ergosumd: part A of %s was re-split, but %s cannot be written (%v); the re-split stays pending\n", name, path, err)
		} else {
			fmt.Fprintf(os.Stderr, "ergosumd: part A of %s re-split to the authority list in use; %s replaced\n", name, path)
		}
	}
	_, err = os.Stdout.Write(resp.Secret)
	return err
}

// replaceFile replaces path atomically with data, keeping its owner and
// mode.
func replaceFile(path string, data []byte) error {
	fi, err := os.Stat(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() //nolint:gosec // the temporary file next to part A
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(fi.Mode().Perm())
	}
	if err == nil && runtime.GOOS != "windows" {
		if uid, gid, ok := owner(fi); ok {
			err = tmp.Chown(uid, gid)
		}
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path) //nolint:gosec // operator-supplied path
}

// secretInfo shows part A without the secret; it needs no daemon.
func secretInfo(args []string) error {
	f := newSecretFlags("info", readFileUsage, false)
	cli.Usage(f.fs, "ergosumd secret info NAME [-file PATH]", `Shows what part A holds, without the secret: name, identity, trust domain,
threshold, the pinned instances and whether a recovery copy exists. It asks
no daemon and no instance.
`, nameArg)
	name, path, err := f.parse(args)
	if err != nil {
		return err
	}
	data, err := f.readPartA(name, path)
	if err != nil {
		return err
	}
	s, err := secret.Parse(data)
	if err != nil {
		return err
	}
	recovery := "none"
	if s.Recovery != "" {
		recovery = "age file"
	}
	fmt.Printf("name:         %s\nidentity:     %s\ntrust domain: %s\nthreshold:    %d of %d\nrecovery:     %s\npins:\n",
		s.Name, s.Identity, s.TrustDomain, s.Threshold, len(s.Pins), recovery)
	for i, p := range s.Pins {
		kid := "?"
		if rk, _, err := p.ReleaseKeyPayload(); err == nil {
			kid = rk.Authority
		}
		fmt.Printf("  %d. %s (kid %s)\n", i+1, p.Authority, kid)
	}
	return nil
}
