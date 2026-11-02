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

// secretFlags are the flags every secret command takes.
type secretFlags struct {
	fs     *flag.FlagSet
	config *string
	socket *string
	file   *string
}

func newSecretFlags(name string) *secretFlags {
	fs := flag.NewFlagSet("secret "+name, flag.ExitOnError)
	return &secretFlags{
		fs:     fs,
		config: fs.String("config", defaultConfig, "daemon configuration, for the socket"),
		socket: fs.String("socket", "", "the daemon's secret socket (default: from the configuration)"),
		file:   fs.String("file", "", "part A (default: "+defaultSecretDir+"/NAME)"),
	}
}

// parse takes NAME before or after the flags and returns it with the path
// of part A. Without -file a NAME is required.
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
		return name, *f.file, nil
	case name == "":
		return "", "", errors.New("name a secret, or give -file")
	case !secret.ValidName(name):
		return "", "", fmt.Errorf("bad name %q: lower-case letters, digits and hyphens, at most 63 characters", name)
	}
	return name, filepath.Join(defaultSecretDir, name), nil
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
	f := newSecretFlags("create")
	threshold := f.fs.Int("threshold", 0, "instances needed to open the secret (required)")
	raw := f.fs.Bool("raw", false, "keep a trailing newline of the input")
	var rec recipients
	f.fs.Var(&rec, "recovery", "age X25519 or ssh-ed25519 public key for the recovery copy (repeatable)")
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
	if path == filepath.Join(defaultSecretDir, name) {
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
	return nil
}

// secretGet writes the secret to stdout: the bytes as stored, nothing
// else. On any failure stdout stays empty.
func secretGet(args []string) error {
	f := newSecretFlags("get")
	name, path, err := f.parse(args)
	if err != nil {
		return err
	}
	partA, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
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
	f := newSecretFlags("info")
	_, path, err := f.parse(args)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
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
