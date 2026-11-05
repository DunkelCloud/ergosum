// Command ergosumd is the machine identity daemon. It holds the machine's
// key pair, requests identity tokens from an authority and answers the
// authority's callbacks.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DunkelCloud/ergosum/internal/cli"
	"github.com/DunkelCloud/ergosum/internal/daemon"
	"github.com/DunkelCloud/ergosum/internal/version"
)

const defaultConfig = "/etc/ergosum/ergosumd.yaml"

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  ergosumd run [-config %[1]s] [-log-format json|text]
  ergosumd request [-config %[1]s] [-new-key] [-out FILE]
  ergosumd fingerprint [-config %[1]s]
  ergosumd check [-config %[1]s]
  ergosumd version

Secrets without Vault (part A in %[2]s/NAME unless -file is given):
  ergosumd secret create NAME -threshold K [-recovery RECIPIENT]... [-raw] [-file PATH]
  ergosumd secret get NAME [-file PATH]
  ergosumd secret info NAME [-file PATH]

Run request and fingerprint as the service user (sudo -u ergosum ...):
they create the key on first use. check connects to each authority URL
and fails if one presents another key than the configured one.
secret create reads the secret from stdin and removes one trailing
newline (-raw keeps it); secret get writes it to stdout as stored, and
fits as a password command (restic --password-command and the like).

Each command explains its arguments and flags with -h, such as
  ergosumd secret create -h
`, defaultConfig, defaultSecretDir)
}

func main() {
	// No default command: a call without one, say to see the usage, must not
	// start a second daemon next to the service and write its token file.
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = run(os.Args[2:])
	case "request":
		err = request(os.Args[2:])
	case "fingerprint":
		err = fingerprint(os.Args[2:])
	case "check":
		err = check(os.Args[2:])
	case "secret":
		err = secretCmd(os.Args[2:])
	case "version":
		fmt.Println("ergosumd", version.String())
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ergosumd:", err)
		os.Exit(1)
	}
}

func logger(format string) *slog.Logger {
	if format == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, nil))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, nil))
}

// configFlag registers -config, the daemon configuration.
func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", defaultConfig, "read the daemon configuration from `FILE`: identity, authorities, "+
		"addresses, state_dir, token_file and the other settings (examples/ergosumd.yaml in the repository)")
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := configFlag(fs)
	logFormat := fs.String("log-format", "json", "write the log to stdout in `FORMAT`: json, or text to read by eye")
	cli.Usage(fs, "ergosumd run [-config FILE] [-log-format json|text]", `Runs the daemon, as its service does: requests an identity token from the
authorities, writes it to token_file and renews it from half its lifetime
on, answering the authorities' callbacks on the callback port while a
request is in flight. It answers "ergosumd secret" on secret_socket and
holds the secrets opened there. It stops on SIGINT or SIGTERM. Start it
through the service, not by hand next to it.
`)
	_ = fs.Parse(args)
	cfg, err := daemon.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	d, err := daemon.New(cfg, daemon.Options{Logger: logger(*logFormat)})
	if err != nil {
		return err
	}
	defer d.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return d.Run(ctx)
}

// request writes a binding request for this machine, for an administrator
// to complete with "ergosum bind".
func request(args []string) error {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	cfgPath := configFlag(fs)
	newKey := fs.Bool("new-key", false, "request a binding for a new key: creates the next key next to the "+
		"current one (identity.key.new in state_dir), or names the one an earlier -new-key created. The "+
		"daemon keeps the current key until every authority that answers names the new one in its binding.")
	out := fs.String("out", "", "write the request to `FILE` instead of stdout; an existing file is never overwritten")
	cli.Usage(fs, "ergosumd request [-config FILE] [-new-key] [-out FILE]", `Writes a binding request for this machine: its identity, the fingerprint of
its key and the checks it proposes from where it stands (its tailnet name,
fixed addresses as ip checks, the networks of DHCP addresses as net
checks). An ergosum administrator checks it and records it with
"ergosum bind FILE". Run it as the service user, since it creates the key
on first use:
  sudo -u ergosum ergosumd request -out host1.txt
`)
	_ = fs.Parse(args)
	cfg, err := daemon.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if *out != "" {
		if _, err := os.Stat(*out); err == nil {
			return fmt.Errorf("%s exists", *out)
		}
	}
	d, err := daemon.New(cfg, daemon.Options{Logger: slog.New(slog.NewTextHandler(os.Stderr, nil))})
	if err != nil {
		return err
	}
	text, err := d.Request(context.Background(), *newKey, time.Now())
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(text)
		return err
	}
	return os.WriteFile(*out, text, 0o644) //nolint:gosec // holds no secret
}

// fingerprint prints the identity key fingerprint, creating the key on
// first use, so that provisioning can read it for the binding.
func fingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	cfgPath := configFlag(fs)
	cli.Usage(fs, "ergosumd fingerprint [-config FILE]", `Prints the fingerprint of the machine's key (SHA256:...), as its binding
names it. Run it as the service user, since it creates the key on first
use: sudo -u ergosum ergosumd fingerprint
`)
	_ = fs.Parse(args)
	cfg, err := daemon.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	d, err := daemon.New(cfg, daemon.Options{Logger: slog.New(slog.NewTextHandler(os.Stderr, nil))})
	if err != nil {
		return err
	}
	fmt.Println(d.Fingerprint())
	return nil
}

// check prints the key each authority URL presents. A URL with another key
// than the configured one fails the check; one that is not reached does
// not, since a new machine may reach its authorities only later.
func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfgPath := configFlag(fs)
	cli.Usage(fs, "ergosumd check [-config FILE]", `Connects to each authority URL of the configuration and prints the key it
presents. It fails if one presents another key than the configured one; a
URL that cannot be reached does not fail it, since a new machine may reach
its authorities only later. An authority logs its key when it starts.
`)
	_ = fs.Parse(args)
	cfg, err := daemon.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	wrong := false
	for _, c := range daemon.CheckKeys(context.Background(), cfg) {
		switch {
		case c.Err != nil:
			fmt.Printf("%s: not reached: %v\n", c.URL, c.Err)
		case c.Got != c.Want:
			fmt.Printf("%s: presents %s, not the configured %s\n", c.URL, c.Got, c.Want)
			wrong = true
		default:
			fmt.Printf("%s: presents %s, as configured\n", c.URL, c.Got)
		}
	}
	if wrong {
		return errors.New("the key or the URL of an authority is wrong; an authority logs its key when it starts")
	}
	return nil
}
