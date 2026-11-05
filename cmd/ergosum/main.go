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
	"github.com/DunkelCloud/ergosum/internal/cli"
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
  ergosum keygen -out FILE [-encrypt] [-exchange] [-from PLAIN-KEY-FILE]
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
  ergosum authorities                                    the authority lists, and whether they agree

Releases (same configuration: release_key, release_signers):
  ergosum release sign [-key KEY] [-signers FILE] [-yes] [-force] SHA256SUMS   sign a release's checksums
  ergosum release verify [-signers FILE] DIR                                  check a downloaded release

Each command explains its arguments and flags with -h, such as
  ergosum bind -h
  ergosum journal sync -h
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
	case "authorities":
		err = authorities(os.Args[2:])
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

// socketFlag registers -socket, the control socket of the local instance.
func socketFlag(fs *flag.FlagSet) *string {
	return fs.String("socket", defaultSocket, "reach the instance on its control socket `PATH`: control_socket in its configuration")
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfig, "read the instance configuration from `FILE`: instance, listen, its keys, "+
		"replication peers and the other settings (examples/serve.yaml in the repository)")
	logFormat := fs.String("log-format", "json", "write the log to stdout in `FORMAT`: json, or text to read by eye")
	cli.Usage(fs, "ergosum serve [-config FILE] [-log-format json|text]", `Runs an authority instance, as its service does: checks machines against
their bindings and issues identity tokens, releases the shares of sealed
secrets if it has an exchange key, and replicates the journal with its
peers. With an encrypted key it starts sealed and issues nothing until
"ergosum unseal". It stops on SIGINT or SIGTERM.
`)
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
	socket := socketFlag(fs)
	cli.Usage(fs, "ergosum unseal [-socket PATH]", `Opens the encrypted keys of the instance on this host, which starts sealed
after every start: reads the passphrase from the terminal, or one line from
stdin, and hands it to the instance over its control socket. Run it as
ergosum-authority or root on the instance's host, in a container with
  docker exec -it CONTAINER ergosum unseal
`)
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
	out := fs.String("out", "", "write the private key to `FILE` (required); an existing file is never overwritten")
	encrypt := fs.Bool("encrypt", false, "encrypt the key with a passphrase, asked twice on the terminal. The "+
		"instance then starts sealed and needs \"ergosum unseal\" after every start. An exchange key takes "+
		"the passphrase of the signing key, so that one unseal opens both.")
	exchange := fs.Bool("exchange", false, "write an exchange key, for exchange_key_file, instead of a signing key: "+
		"with it the instance takes part in releasing secrets (ergosumd secret). Never back it up: next to a "+
		"copy of a machine's part A it opens the secret without any check.")
	from := fs.String("from", "", "encrypt the existing plain key `PLAIN-KEY-FILE` instead of generating one; "+
		"needs -encrypt, and with -exchange it is an exchange key. Key ID and fingerprint stay the same, so "+
		"Vault and the authority lists stay as they are. A key that is encrypted already is refused.")
	cli.Usage(fs, "ergosum keygen -out FILE [-encrypt] [-exchange] [-from PLAIN-KEY-FILE]", `Writes a new key of an authority instance to FILE, with mode 0600 for the
user who runs it. For a signing key it prints the key ID, the fingerprint
for the daemons' and the administrators' authorities, and the public key
in PEM for the token verifier and the instance's peers. Hand the file to
the service user before the first start:
  chgrp ergosum-authority FILE && chmod 0640 FILE
`)
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s exists; refusing to overwrite a key", *out)
	}
	if *from != "" {
		if !*encrypt {
			return errors.New("-from needs -encrypt: it encrypts an existing key")
		}
		prompt := "New passphrase: "
		if *exchange {
			prompt = "Passphrase of the signing key: "
		}
		pass, err := readPassphrase(prompt, true)
		if err != nil {
			return err
		}
		defer wipe(pass)
		data, summary, err := encryptExisting(*from, *exchange, pass)
		if err != nil {
			return err
		}
		if err := keys.WriteFileAtomic(*out, data, 0o600); err != nil {
			return err
		}
		fmt.Print(summary)
		return nil
	}
	if *exchange {
		return keygenExchange(*out, *encrypt)
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

// keygenExchange writes an exchange key (ADR 0004). Encrypted, it takes the
// signing key's passphrase, so that one unseal opens both.
func keygenExchange(out string, encrypt bool) error {
	k, err := keys.GenerateExchangeKey()
	if err != nil {
		return err
	}
	var data []byte
	if encrypt {
		pass, err := readPassphrase("Passphrase of the signing key: ", true)
		if err != nil {
			return err
		}
		defer wipe(pass)
		data, err = keys.EncryptExchangeKeyPEM(k, pass)
		if err != nil {
			return err
		}
	} else if data, err = keys.MarshalExchangeKeyPEM(k); err != nil {
		return err
	}
	if err := keys.WriteFileAtomic(out, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("exchange key written to %s; set exchange_key_file and keep the file out of every backup\n", out)
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
