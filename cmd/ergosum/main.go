// Command ergosum runs the authority (serve) and its operator tooling.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/DunkelCloud/ergosum/internal/authority"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/version"
)

const (
	defaultConfig = "/etc/ergosum/serve.yaml"
	defaultSocket = "/var/lib/ergosum-authority/control.sock"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  ergosum serve [-config %[1]s] [-log-format json|text]
  ergosum unseal [-socket %[2]s]
  ergosum keygen -out FILE [-encrypt]
  ergosum version

Journal of the local instance (through its control socket):
  ergosum journal state      [-socket %[2]s]
  ergosum journal checkpoint [-socket %[2]s]
  ergosum journal compact    [-socket %[2]s]
  ergosum journal sync -from PEER [-from PEER...] [-socket %[2]s]
  ergosum journal export [-out FILE] [-archive] [-socket %[2]s]

Bindings, from an administrator's machine (configuration: %[3]s):
  ergosum bind [-sign-key KEY] [-yes] [-text OUT] FILE   sign and record a binding file
  ergosum revoke [-out FILE] NAME                        revoke a binding
  ergosum show [-out FILE] NAME                          current binding, in the file format
  ergosum list                                           all bindings

Releases (same configuration: release_key, release_signers):
  ergosum release sign [-key KEY] [-signers FILE] [-yes] SHA256SUMS   sign a release's checksums
  ergosum release verify [-signers FILE] DIR                          check a downloaded release
`, defaultConfig, defaultSocket, defaultAdminConfig())
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "unseal":
		err = unseal(os.Args[2:])
	case "keygen":
		err = keygen(os.Args[2:])
	case "journal":
		err = journalCmd(os.Args[2:])
	case "bind":
		err = bind(os.Args[2:])
	case "revoke":
		err = revoke(os.Args[2:])
	case "show":
		err = show(os.Args[2:])
	case "list":
		err = list(os.Args[2:])
	case "release":
		err = releaseCmd(os.Args[2:])
	case "version":
		fmt.Println("ergosum", version.String())
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ergosum:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfig, "configuration file")
	logFormat := fs.String("log-format", "json", "log format: json or text")
	_ = fs.Parse(args)
	cfg, err := authority.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	var log *slog.Logger
	if *logFormat == "text" {
		log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	} else {
		log = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	a, err := authority.New(cfg, authority.Options{Logger: log})
	if err != nil {
		return err
	}
	defer func() { _ = a.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.Run(ctx)
}

// unseal sends the passphrase to the local instance. Only a local process
// with access to the socket can do this.
func unseal(args []string) error {
	fs := flag.NewFlagSet("unseal", flag.ExitOnError)
	socket := fs.String("socket", defaultSocket, "control socket of the running instance")
	_ = fs.Parse(args)
	pass, err := readPassphrase("Passphrase: ", false)
	if err != nil {
		return err
	}
	defer wipe(pass)
	if err := authority.UnsealVia(context.Background(), *socket, pass); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "unsealed")
	return nil
}

// keygen creates an instance signing key and prints what Vault and the
// daemons need: the public key (PEM), the key ID and the fingerprint.
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "file to write the private key to (must not exist)")
	encrypt := fs.Bool("encrypt", false, "encrypt the key with a passphrase; the instance then starts sealed")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s exists; refusing to overwrite a signing key", *out)
	}
	k, err := keys.Generate()
	if err != nil {
		return err
	}
	var data []byte
	if *encrypt {
		pass, err := readPassphrase("New passphrase: ", true)
		if err != nil {
			return err
		}
		defer wipe(pass)
		data, err = keys.EncryptPEM(k, pass)
		if err != nil {
			return err
		}
	} else if data, err = keys.MarshalPrivatePEM(k); err != nil {
		return err
	}
	if err := keys.WriteFileAtomic(*out, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("kid:         %s\nfingerprint: %s\n\n%s", keys.Thumbprint(&k.PublicKey), keys.Fingerprint(&k.PublicKey), keys.MarshalPublicPEM(&k.PublicKey))
	return nil
}

func readPassphrase(prompt string, confirm bool) ([]byte, error) {
	fd := int(os.Stdin.Fd()) //nolint:gosec // file descriptors fit in int
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return nil, fmt.Errorf("reading passphrase from stdin: %w", err)
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Repeat: ")
		again, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		defer wipe(again)
		if !bytes.Equal(pass, again) {
			return nil, errors.New("passphrases differ")
		}
	}
	if len(pass) == 0 {
		return nil, errors.New("empty passphrase")
	}
	return pass, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
