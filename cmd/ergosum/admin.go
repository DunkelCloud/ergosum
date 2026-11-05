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
	"github.com/DunkelCloud/ergosum/internal/cli"
	"github.com/DunkelCloud/ergosum/internal/keys"
)

// multiFlag collects a repeated flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

// adminFlags are the flags that the administrator commands share.
type adminFlags struct {
	config       string
	trustDomain  string
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
	fs.StringVar(&f.config, "config", defaultAdminConfig(), "read the administrator configuration from `FILE`: "+
		"trust_domain, authorities and sign_key. A missing default file is no error; ERGOSUM_ADMIN_CONFIG sets "+
		"another default.")
	fs.StringVar(&f.trustDomain, "trust-domain", "", "take `DOMAIN` (such as example.com) as the authorities' "+
		"trust domain, instead of trust_domain; the authorities must serve the same")
	fs.StringVar(&f.authority, "authority", "", "ask the authority at `URL` (https://HOST:7432) instead of the "+
		"configured ones; needs -authority-key")
	fs.StringVar(&f.authorityKey, "authority-key", "", "the key `FINGERPRINT` (SHA256:...) that the authority "+
		"at -authority must present, as \"ergosum keygen\" printed it")
	if signs {
		fs.StringVar(&f.signKey, "sign-key", "", "sign with `KEY` instead of sign_key: a public key, as a file "+
			"or the key line, whose private key ssh-agent holds, or else the private key file next to it; or a "+
			"private key file")
		fs.StringVar(&f.keygen, "ssh-keygen", "ssh-keygen", "the ssh-keygen `PROGRAM` that signs with a private key file")
		fs.BoolVar(&f.yes, "yes", false, "sign without asking; without a terminal, signing needs it")
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
	if f.trustDomain != "" {
		cfg.TrustDomain = f.trustDomain
	}
	if f.authority != "" {
		cfg.Authorities = []admin.Authority{{URL: f.authority, Key: f.authorityKey}}
	}
	if f.signKey != "" {
		cfg.SignKey = f.signKey
	}
	return cfg, nil
}

// client builds the client of the configured authorities.
func (f *adminFlags) client() (*admin.Client, admin.Config, error) {
	cfg, err := f.load()
	if err != nil {
		return nil, cfg, err
	}
	if len(cfg.Authorities) == 0 {
		if _, err := os.Stat(f.config); errors.Is(err, os.ErrNotExist) {
			return nil, cfg, fmt.Errorf("no authority: the configuration %s does not exist; create it, point ERGOSUM_ADMIN_CONFIG or -config at one, or give -authority and -authority-key", f.config)
		}
		return nil, cfg, fmt.Errorf("no authority: configure one in %s or give -authority and -authority-key", f.config)
	}
	if cfg.TrustDomain == "" {
		return nil, cfg, fmt.Errorf("no trust domain: set trust_domain in %s or give -trust-domain", f.config)
	}
	client, err := admin.NewClient(cfg)
	return client, cfg, err
}

// tool builds the administrator tool from the flags and the configuration.
// It adds the instances that the authorities' list names and the
// configuration does not.
func (f *adminFlags) tool() (*admin.Tool, error) {
	client, cfg, err := f.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	list, added, err := client.Expand(ctx)
	if err != nil {
		return nil, err
	}
	if len(added) > 0 {
		fmt.Fprintf(os.Stderr, "The authority list (serial %d) names %d more authorities, asked as well:\n", list.Serial, len(added))
		for _, a := range added {
			fmt.Fprintf(os.Stderr, "  %s (%s)\n", a.URL, a.Key)
		}
	}
	t := &admin.Tool{Client: client, Out: os.Stderr}
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

// identityArg is the NAME of revoke and show.
var identityArg = cli.Arg{Name: "NAME", Text: "the machine's identity, as its binding names it (host1.example.com)"}

// bind implements "ergosum bind FILE".
func bind(args []string) error {
	fs := flag.NewFlagSet("bind", flag.ExitOnError)
	var af adminFlags
	af.register(fs, true)
	text := fs.String("text", "", "complete FILE and write the text to sign to `OUT`, for signing by hand "+
		"(ssh-keygen -Y sign -n ergosum-binding OUT); signs nothing")
	cli.Usage(fs, "ergosum bind [flags] FILE", `Takes a binding file one step further: adds kind, trust domain and the next
epoch, shows the text to sign and what changes, signs with your key, and
records the event once enough administrators have signed. The next
administrator runs the same command on the same file.
`, cli.Arg{Name: "FILE", Text: "the binding file: a request from \"ergosumd request\", a binding from " +
		"\"ergosum show -out\" or a revocation from \"ergosum revoke\", edited as needed, or one that " +
		"another administrator has signed. bind completes it and appends the signature, and once it is " +
		"recorded, where."})
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
	out := fs.String("out", "", "write the revocation to `FILE` instead of NAME.revoke.txt in the working "+
		"directory; an existing file is refused")
	cli.Usage(fs, "ergosum revoke [flags] NAME", `Revokes the binding of NAME: shows what it ends, writes the revocation to a
file and continues as "ergosum bind" on it. If the registry demands more
approvals, the next administrator runs "ergosum bind" on the same file.
Every instance stops issuing to NAME as soon as the revocation reaches it;
a token already issued stays valid until it expires.
`, identityArg)
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
	return t.Revoke(ctx, fs.Arg(0), *out)
}

// show implements "ergosum show NAME".
func show(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	var af adminFlags
	af.register(fs, false)
	out := fs.String("out", "", "write the binding to `FILE` instead of stdout; an existing file is never overwritten")
	cli.Usage(fs, "ergosum show [flags] NAME", `Prints the current binding of NAME in the binding file format: epoch, key,
checks and who approved it. Edited and passed to "ergosum bind", it
changes the binding, for a new address, another network or another check.
`, identityArg)
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
	cli.Usage(fs, "ergosum list [flags]", `Lists every binding with identity, epoch, state, key and checks, and names
the identities on which the authorities disagree.
`)
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
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

// authorities implements "ergosum authorities": the authority list of
// every configured authority, and whether they agree.
func authorities(args []string) error {
	fs := flag.NewFlagSet("authorities", flag.ExitOnError)
	var af adminFlags
	af.register(fs, false)
	cli.Usage(fs, "ergosum authorities [flags]", `Shows the authority list that each configured authority serves, and
whether they agree: which listed instances are not configured here, and
which configured ones the list lacks. It fails if the lists disagree.
`)
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	client, cfg, err := af.client()
	if err != nil {
		return err
	}
	ctx, cancel := adminContext()
	defer cancel()
	answers, reach, err := client.AuthorityLists(ctx)
	if err != nil {
		return err
	}
	for _, a := range answers {
		if a.List == nil {
			fmt.Printf("%s serves no list\n", a.From)
		} else {
			fmt.Printf("%s serves serial %d with %d instances\n", a.From, a.List.Serial, len(a.List.Authorities))
		}
	}
	for _, e := range reach.Unreachable {
		fmt.Printf("unreachable: %v\n", e)
	}
	list, agreeErr := admin.AgreedList(answers)
	if list != nil {
		configured := map[string]bool{}
		for _, a := range cfg.Authorities {
			configured[a.Key] = true
		}
		fmt.Printf("\nList (serial %d, trust domain %s):\n", list.Serial, list.TrustDomain)
		for _, la := range list.Authorities {
			note := ""
			if !configured[la.Key] {
				note = "  (not configured here)"
			}
			fmt.Printf("  %s%s\n", la.Key, note)
			for _, u := range la.URLs {
				fmt.Printf("    %s\n", u)
			}
		}
		for _, a := range cfg.Authorities {
			if !list.Lists(a.Key) {
				fmt.Printf("  configured here, missing from the list: %s (%s)\n", a.URL, a.Key)
			}
		}
	}
	return agreeErr
}
