// Command ergosumd is the machine identity daemon. It holds the machine's
// key pair, requests identity tokens from an authority and answers the
// authority's callbacks.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/DunkelCloud/ergosum/internal/daemon"
	"github.com/DunkelCloud/ergosum/internal/version"
)

const defaultConfig = "/etc/ergosum/ergosumd.yaml"

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  ergosumd [run] [-config %[1]s] [-log-format json|text]
  ergosumd fingerprint [-config %[1]s]
  ergosumd version
`, defaultConfig)
}

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "run":
		err = run(args)
	case "fingerprint":
		err = fingerprint(args)
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

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfig, "configuration file")
	logFormat := fs.String("log-format", "json", "log format: json or text")
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

// fingerprint prints the identity key fingerprint, creating the key on
// first use, so that provisioning can read it for the binding.
func fingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfig, "configuration file")
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
