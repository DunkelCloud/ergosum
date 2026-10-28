package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/DunkelCloud/ergosum/internal/admin"
	"github.com/DunkelCloud/ergosum/internal/journal"
)

// multiFlag collects a repeated flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

// adminFlags are the flags that bind, revoke and sign share.
type adminFlags struct {
	config       string
	authority    string
	authorityKey string
	trustDomain  string
	signKey      string
	keygen       string
	out          string
	submit       bool
	yes          bool
}

func defaultAdminConfig() string {
	if p := os.Getenv("ERGOSUM_ADMIN_CONFIG"); p != "" {
		return p
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "ergosum", "admin.yaml")
	}
	return ""
}

func (f *adminFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.config, "config", defaultAdminConfig(), "administrator configuration (trust_domain, authorities)")
	fs.StringVar(&f.authority, "authority", "", "authority URL, instead of the configured ones")
	fs.StringVar(&f.authorityKey, "authority-key", "", "key fingerprint of -authority (SHA256:...)")
	fs.StringVar(&f.trustDomain, "trust-domain", "", "trust domain, instead of the configured one")
	fs.StringVar(&f.signKey, "sign-key", "", "sign with this key: private key file, security key handle, or public key held by ssh-agent")
	fs.StringVar(&f.keygen, "ssh-keygen", "ssh-keygen", "ssh-keygen program")
	fs.StringVar(&f.out, "out", "", "event file to write (\"-\" for stdout)")
	fs.BoolVar(&f.submit, "submit", false, "write the event to the first reachable authority")
	fs.BoolVar(&f.yes, "yes", false, "sign without asking")
}

// load reads the configuration; a missing default file is not an error.
func (f *adminFlags) load() (admin.Config, error) {
	var cfg admin.Config
	if f.config != "" {
		c, err := admin.LoadConfig(f.config)
		switch {
		case err == nil:
			cfg = c
		case errors.Is(err, os.ErrNotExist) && f.config == defaultAdminConfig():
		default:
			return cfg, err
		}
	}
	if f.authority != "" {
		cfg.Authorities = []admin.Authority{{URL: f.authority, Key: f.authorityKey}}
	}
	if f.trustDomain != "" {
		cfg.TrustDomain = f.trustDomain
	}
	return cfg, nil
}

func (f *adminFlags) client(cfg admin.Config) (*admin.Client, error) {
	if len(cfg.Authorities) == 0 {
		return nil, nil
	}
	return admin.NewClient(cfg)
}

func adminContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// bindOrRevoke implements "ergosum bind" and "ergosum revoke".
func bindOrRevoke(kind string, args []string) error {
	fs := flag.NewFlagSet(strings.TrimPrefix(kind, "binding."), flag.ExitOnError)
	var af adminFlags
	af.register(fs)
	identity := fs.String("identity", "", "identity (lower-case DNS name)")
	epoch := fs.Uint64("epoch", 0, "epoch; default: the current epoch plus one, read from an authority")
	var key string
	var checks multiFlag
	if kind == journal.KindBindingSet {
		fs.StringVar(&key, "key", "", "daemon key fingerprint (from \"ergosumd fingerprint\")")
		fs.Var(&checks, "check", "callback check type:target, repeatable (tailnet:NAME, ip:ADDR[:PORT], net:PREFIX)")
	}
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	cfg, err := af.load()
	if err != nil {
		return err
	}
	if cfg.TrustDomain == "" {
		return errors.New("no trust domain: set trust_domain in the configuration or give -trust-domain")
	}
	client, err := af.client(cfg)
	if err != nil {
		return err
	}
	var cs []journal.Check
	for _, c := range checks {
		ch, err := admin.ParseCheck(c)
		if err != nil {
			return err
		}
		cs = append(cs, ch)
	}
	ctx, cancel := adminContext()
	defer cancel()
	e, cur, err := admin.NewEvent(ctx, client, kind, cfg.TrustDomain, *identity, *epoch, key, cs)
	if err != nil {
		return err
	}
	if cur != nil {
		fmt.Fprintf(os.Stderr, "current: %s at epoch %d (key %s)\n", cur.Kind, cur.Epoch, orNone(cur.Key))
	}
	out := af.out
	if out == "" {
		out = fmt.Sprintf("%s.epoch%d.json", e.Identity, e.Epoch)
	}
	return signWriteSubmit(ctx, &af, client, e, out)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// sign implements "ergosum sign": merge the signatures of event files,
// optionally add one, write and submit.
func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	var af adminFlags
	af.register(fs)
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("usage: ergosum sign [flags] EVENT.json [MORE.json...]")
	}
	var events []*journal.BindingEvent
	for _, p := range fs.Args() {
		e, err := admin.ReadEvent(p)
		if err != nil {
			return err
		}
		events = append(events, e)
	}
	e, err := admin.Merge(events...)
	if err != nil {
		return err
	}
	cfg, err := af.load()
	if err != nil {
		return err
	}
	var client *admin.Client
	if af.submit {
		if client, err = af.client(cfg); err != nil {
			return err
		}
	}
	// Without -out the result goes back to the first file, unless the call
	// only submits one event unchanged: then there is nothing to write, and
	// the file may sit where it cannot be written.
	out := af.out
	if out == "" && (fs.NArg() > 1 || af.signKey != "" || !af.submit) {
		out = fs.Arg(0)
	}
	ctx, cancel := adminContext()
	defer cancel()
	return signWriteSubmit(ctx, &af, client, e, out)
}

func signWriteSubmit(ctx context.Context, af *adminFlags, client *admin.Client, e *journal.BindingEvent, out string) error {
	canonical, err := e.Canonical()
	if err != nil {
		return err
	}
	signers, err := admin.Signers(e)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", indent(string(canonical)))
	for _, s := range signers {
		fmt.Fprintf(os.Stderr, "signed by %s\n", s)
	}
	if af.signKey != "" {
		if !af.yes {
			if err := confirm("Sign this event?"); err != nil {
				return err
			}
		}
		fp, err := admin.AddSignature(ctx, e, admin.SSHKeygen(af.keygen, af.signKey))
		switch {
		case errors.Is(err, admin.ErrAlreadySigned):
			fmt.Fprintf(os.Stderr, "%s has signed already\n", fp)
		case err != nil:
			return err
		default:
			fmt.Fprintf(os.Stderr, "signed by %s\n", fp)
		}
	}
	if out != "" {
		if err := admin.WriteEvent(out, e); err != nil {
			return err
		}
		if out != "-" {
			fmt.Fprintf(os.Stderr, "event written to %s (%d signatures)\n", out, len(e.Signatures))
		}
	}
	if !af.submit {
		return nil
	}
	if client == nil {
		return errors.New("-submit needs an authority: configure one or give -authority and -authority-key")
	}
	r, from, err := client.Submit(ctx, e)
	if err != nil {
		return err
	}
	verb := "recorded"
	if r.Duplicate {
		verb = "already recorded"
	}
	fmt.Fprintf(os.Stderr, "%s by %s as %s/%d\n", verb, from, r.Origin, r.Seq)
	return nil
}

func indent(s string) string {
	return "    " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n    ")
}

// confirm asks on the terminal; without one, signing needs -yes.
func confirm(question string) error {
	fd := int(os.Stdin.Fd()) //nolint:gosec // file descriptors fit in int
	if !term.IsTerminal(fd) {
		return errors.New("not a terminal: read the event above and sign with -yes")
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
		return errors.New("not signed")
	}
	return nil
}
