package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/DunkelCloud/ergosum/internal/cli"
	"github.com/DunkelCloud/ergosum/internal/daemon"
	"github.com/DunkelCloud/ergosum/internal/secret"
)

// The flags of replace and edit, the commands that put a new secret in
// place of an existing one.
const (
	changeFileUsage = "replace part A at `PATH` instead of " + defaultSecretDir + "/NAME: needed for a part A that " +
		"create wrote elsewhere. A relative PATH is taken from the working directory. With -file, NAME may be left out."
	changeRecoveryUsage = "seal a recovery copy of the new secret to `RECIPIENT`, as create does: an age X25519 " +
		"public key (age1...) or an ssh-ed25519 public key line (\"ssh-ed25519 AAAA... comment\", quoted as one " +
		"argument). Repeat -recovery for more recipients. Needed if part A has a recovery copy: part A does not " +
		"name its recipients, and the copy of the old secret cannot be carried over. Given for a part A without " +
		"one, it adds the copy."
)

func secretReplace(args []string) error {
	f := newSecretFlags("replace", changeFileUsage, true)
	raw := f.fs.Bool("raw", false, "keep the input as it is; without -raw, one trailing newline (LF or CRLF), "+
		"as echo or an editor leaves it, is removed")
	var rec recipients
	f.fs.Var(&rec, "recovery", changeRecoveryUsage)
	cli.Usage(f.fs, "ergosumd secret replace NAME [-recovery RECIPIENT]... [-raw] [-file PATH]",
		`Seals a new secret read from stdin, at most 64 KiB, in place of an existing
one: a new part A with the same name and threshold, pinned to every
instance of the authority list that hands out a release key for the
machine. replace puts it in place of the file in one step and keeps the
file's owner and mode. It refuses an empty input, and whatever fails, part
A stays as it was.
If part A has a recovery copy, replace needs its recipients again with
-recovery and seals a copy of the new secret to them. Without -recovery it
changes nothing: the way back is never lost unnoticed.
replace is no revocation. A copy of the old part A, in a backup for
example, still opens the old secret. Run it as root, or as a user that may
write part A and use secret_socket:
  printf '%s\n' "$PASSWORD" | ergosumd secret replace restic \
    -recovery 'age1...'
`, nameArg)
	name, path, err := f.parse(args)
	if err != nil {
		return err
	}
	old, s, err := f.existing(name, path, rec)
	if err != nil {
		return err
	}
	plain, err := readSecret(os.Stdin, *raw)
	if err != nil {
		return asItWas(err)
	}
	return f.reseal(path, old, s, plain, nil, rec)
}

// asItWas marks an error of replace or edit that left part A untouched.
func asItWas(err error) error { return fmt.Errorf("%w; part A is as it was", err) }

// existing reads the part A that replace and edit change. It refuses a
// part A that holds another secret than the one named, one whose recovery
// copy the command would lose, and recipients that cannot be used.
func (f *secretFlags) existing(name, path string, rec recipients) ([]byte, *secret.Sealed, error) {
	partA, err := f.readPartA(name, path)
	if err != nil {
		return nil, nil, err
	}
	s, err := secret.Parse(partA)
	if err != nil {
		return nil, nil, err
	}
	if name != "" && name != s.Name {
		return nil, nil, asItWas(fmt.Errorf("%s holds the secret %s, not %s", path, s.Name, name))
	}
	if s.Recovery != "" && len(rec) == 0 {
		return nil, nil, asItWas(fmt.Errorf("part A of %s has a recovery copy and does not name its recipients: "+
			"give them again with -recovery, so that the new secret has one too", s.Name))
	}
	if err := secret.CheckRecipients(rec); err != nil {
		return nil, nil, asItWas(err)
	}
	return partA, s, nil
}

// reseal seals plain in place of the secret of the part A at path, which
// held old when the command read it and parses to s: a new part A with the
// name and threshold of s, pinned to the instances in use now, takes the
// place of the file, with its owner and mode. The daemon is told to forget
// the part A that was replaced.
//
// was is the secret that old opened, for a command that showed it and took
// the new one in return (edit), or nil. With was, a part A that changed
// meanwhile is replaced only if it still opens that secret.
func (f *secretFlags) reseal(path string, old []byte, s *secret.Sealed, plain, was []byte, rec recipients) error {
	switch {
	case len(plain) == 0:
		return asItWas(errors.New("the new secret is empty"))
	case len(plain) > secret.MaxSecret:
		return asItWas(fmt.Errorf("the secret is longer than %d bytes", secret.MaxSecret))
	}
	recovery, err := secret.Recovery(plain, rec)
	if err != nil {
		return asItWas(err)
	}
	socket := f.socketPath()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	resp, err := daemon.CallSecret(ctx, socket, daemon.SecretRequest{
		Op: "create", Name: s.Name, Threshold: s.Threshold, Secret: plain, Recovery: recovery,
	})
	if err != nil {
		return asItWas(err)
	}
	n, err := secret.Parse(resp.PartA)
	if err == nil && (n.Identity != s.Identity || n.TrustDomain != s.TrustDomain) {
		err = fmt.Errorf("part A is sealed for %s in trust domain %s, this machine is %s in %s",
			s.Identity, s.TrustDomain, n.Identity, n.TrustDomain)
	}
	var current []byte
	if err == nil {
		current, err = f.current(s.Name, path, old, was)
	}
	if err == nil {
		err = replaceFile(path, resp.PartA)
	}
	if err != nil {
		// The daemon holds the new secret open, and no file asks for it.
		forget(ctx, socket, resp.PartA)
		return asItWas(err)
	}
	forget(ctx, socket, old, current)
	recoveryCopy := "without a recovery copy"
	if n.Recovery != "" {
		recoveryCopy = "with a recovery copy"
	}
	fmt.Fprintf(os.Stderr, "part A of %s replaced in %s: threshold %d of %d pinned instances, %s\n",
		n.Name, path, n.Threshold, len(n.Pins), recoveryCopy)
	return nil
}

// current returns part A as it lies at path now. It may no longer be old:
// the get of a consumer may have put a re-split part A there, or another
// command another secret. With was, the secret that old opened, current
// fails unless part A still opens that secret; what the caller made of was
// would otherwise overwrite a change it never saw.
func (f *secretFlags) current(name, path string, old, was []byte) ([]byte, error) {
	now, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil || was == nil || bytes.Equal(now, old) {
		return now, err
	}
	plain, now, err := f.open(name, path, now)
	if err != nil {
		return nil, fmt.Errorf("part A changed meanwhile and does not open: %w", err)
	}
	if !bytes.Equal(plain, was) {
		return nil, errors.New("another command changed the secret meanwhile")
	}
	return now, nil
}

// forget tells the daemon which part A is no longer in use, so that it
// drops the secret from memory and from its refreshes. Part A is already
// where it belongs; a daemon that cannot be told only keeps the secret
// until it restarts.
func forget(ctx context.Context, socket string, partA ...[]byte) {
	var last []byte
	for _, p := range partA {
		if p == nil || bytes.Equal(p, last) {
			continue
		}
		if _, err := daemon.CallSecret(ctx, socket, daemon.SecretRequest{Op: "forget", PartA: p}); err != nil {
			fmt.Fprintf(os.Stderr, "ergosumd: the daemon keeps a secret that is no longer in use in memory until it restarts (%v)\n", err)
			return
		}
		last = p
	}
}
