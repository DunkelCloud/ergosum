package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/DunkelCloud/ergosum/internal/admin"
	"github.com/DunkelCloud/ergosum/internal/keys"
)

// multiFlag collects a repeated flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

// adminFlags are the flags that the administrator commands share.
type adminFlags struct {
	config       string
	authority    string
	authorityKey string
	signKey      string
	keygen       string
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

func (f *adminFlags) register(fs *flag.FlagSet, signs bool) {
	fs.StringVar(&f.config, "config", defaultAdminConfig(), "administrator configuration (authorities, sign_key)")
	fs.StringVar(&f.authority, "authority", "", "authority URL, instead of the configured ones")
	fs.StringVar(&f.authorityKey, "authority-key", "", "key fingerprint of -authority (SHA256:...)")
	if signs {
		fs.StringVar(&f.signKey, "sign-key", "", "sign with this key instead of sign_key: public key held by ssh-agent, or private key file")
		fs.StringVar(&f.keygen, "ssh-keygen", "ssh-keygen", "ssh-keygen program, for private key files")
		fs.BoolVar(&f.yes, "yes", false, "sign without asking")
	}
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
	if f.signKey != "" {
		cfg.SignKey = f.signKey
	}
	return cfg, nil
}

// tool builds the administrator tool from the flags and the configuration.
func (f *adminFlags) tool() (*admin.Tool, error) {
	cfg, err := f.load()
	if err != nil {
		return nil, err
	}
	if len(cfg.Authorities) == 0 {
		return nil, fmt.Errorf("no authority: configure one in %s or give -authority and -authority-key", f.config)
	}
	client, err := admin.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	t := &admin.Tool{Client: client, TrustDomain: cfg.TrustDomain, Out: os.Stderr}
	if cfg.SignKey != "" {
		if t.Key, err = admin.LoadSignKey(cfg.SignKey, f.keygen); err != nil {
			return nil, err
		}
	}
	if !f.yes {
		t.Confirm = confirm
	}
	return t, nil
}

func adminContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// bind implements "ergosum bind FILE".
func bind(args []string) error {
	fs := flag.NewFlagSet("bind", flag.ExitOnError)
	var af adminFlags
	af.register(fs, true)
	text := fs.String("text", "", "complete FILE and write the text to sign to this file, for signing by hand; no signature")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `usage: ergosum bind [flags] FILE

Takes a binding file one step further: adds kind, trust domain and the next
epoch, shows the text to sign and what changes, signs with your key, and
records the event once enough administrators have signed. The next
administrator runs the same command on the same file.

`)
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	t, err := af.tool()
	if err != nil {
		return err
	}
	ctx, cancel := adminContext()
	defer cancel()
	if *text != "" {
		return t.Text(ctx, fs.Arg(0), *text)
	}
	return t.Bind(ctx, fs.Arg(0))
}

// revoke implements "ergosum revoke NAME".
func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	var af adminFlags
	af.register(fs, true)
	out := fs.String("out", "", "revocation file to write (default NAME.revoke.txt)")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: ergosum revoke [flags] NAME")
	}
	t, err := af.tool()
	if err != nil {
		return err
	}
	ctx, cancel := adminContext()
	defer cancel()
	return t.Revoke(ctx, fs.Arg(0), *out)
}

// show implements "ergosum show NAME".
func show(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	var af adminFlags
	af.register(fs, false)
	out := fs.String("out", "", "write to this file instead of stdout (must not exist)")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: ergosum show [flags] NAME")
	}
	t, err := af.tool()
	if err != nil {
		return err
	}
	ctx, cancel := adminContext()
	defer cancel()
	if *out == "" {
		return t.Show(ctx, fs.Arg(0), os.Stdout)
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s exists", *out)
	}
	var b strings.Builder
	if err := t.Show(ctx, fs.Arg(0), &b); err != nil {
		return err
	}
	return keys.WriteFileAtomic(*out, []byte(b.String()), 0o644) //nolint:gosec // holds no secret
}

// list implements "ergosum list".
func list(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	var af adminFlags
	af.register(fs, false)
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		return errors.New("usage: ergosum list [flags]")
	}
	t, err := af.tool()
	if err != nil {
		return err
	}
	ctx, cancel := adminContext()
	defer cancel()
	return t.List(ctx, os.Stdout)
}

// confirm asks on the terminal; without one, signing needs -yes.
func confirm(question string) error {
	fd := int(os.Stdin.Fd()) //nolint:gosec // file descriptors fit in int
	if !term.IsTerminal(fd) {
		return errors.New("not a terminal: read the text above and sign with -yes")
	}
	fmt.Fprintf(os.Stderr, "\n%s [y/N] ", question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
		return errors.New("not signed")
	}
	return nil
}
