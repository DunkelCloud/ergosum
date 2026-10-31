package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/DunkelCloud/ergosum/internal/admin"
	"github.com/DunkelCloud/ergosum/internal/release"
	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

const (
	defaultReleaseKey     = "~/.ssh/ergosum-release.pub"
	defaultReleaseSigners = "/etc/ergosum/release-signers"
)

// releaseCmd implements "ergosum release sign|verify".
func releaseCmd(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "sign":
			return releaseSign(args[1:])
		case "verify":
			return releaseVerify(args[1:])
		}
	}
	return errors.New("usage: ergosum release sign|verify ... (see ergosum help)")
}

// releaseFlags are the flags that sign and verify share.
type releaseFlags struct {
	config  string
	signers string
}

func (f *releaseFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.config, "config", defaultAdminConfig(), "administrator configuration (release_key, release_signers)")
	fs.StringVar(&f.signers, "signers", "", "keys that may sign releases (release-signers from the repository), instead of release_signers")
}

func (f *releaseFlags) load() (admin.Config, error) {
	return (&adminFlags{config: f.config}).load()
}

// signerList reads release-signers: from -signers, the configuration, or
// the place deploy/install.sh uses. ok is false if none is given.
func (f *releaseFlags) signerList(cfg admin.Config) (signers []release.Signer, ok bool, err error) {
	path := f.signers
	if path == "" {
		path = cfg.ReleaseSigners
	}
	if path == "" {
		if _, err := os.Stat(defaultReleaseSigners); err != nil {
			return nil, false, nil
		}
		path = defaultReleaseSigners
	}
	data, err := os.ReadFile(admin.ExpandHome(path)) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, false, err
	}
	signers, err = release.ParseSigners(data)
	return signers, err == nil, err
}

// releaseSign implements "ergosum release sign SHA256SUMS".
func releaseSign(args []string) error {
	fs := flag.NewFlagSet("release sign", flag.ExitOnError)
	var f releaseFlags
	f.register(fs)
	keySpec := fs.String("key", "", "release key, instead of release_key (default "+defaultReleaseKey+"): a public key held by ssh-agent, "+
		"with the private key file next to it if the agent lacks it, or a private key file")
	yes := fs.Bool("yes", false, "sign without asking")
	force := fs.Bool("force", false, "replace an existing "+release.SigFile)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: ergosum release sign [-key KEY] [-signers FILE] [-yes] [-force] SHA256SUMS")
	}
	sumsPath := fs.Arg(0)
	sigPath := sumsPath + ".sig"
	cfg, err := f.load()
	if err != nil {
		return err
	}
	sums, err := os.ReadFile(sumsPath) //nolint:gosec // operator-supplied path
	if err != nil {
		return err
	}
	entries, err := release.ParseSums(sums)
	if err != nil {
		return err
	}
	if _, err := os.Stat(sigPath); err == nil && !*force {
		return fmt.Errorf("%s exists; -force replaces it", sigPath)
	}
	signers, haveSigners, err := f.signerList(cfg)
	if err != nil {
		return err
	}
	spec := *keySpec
	if spec == "" {
		spec = cfg.ReleaseKey
	}
	if spec == "" {
		spec = defaultReleaseKey
	}

	fmt.Fprintf(os.Stderr, "%s lists %d files:\n", sumsPath, len(entries))
	for _, e := range entries {
		fmt.Fprintf(os.Stderr, "  %s  %s\n", e.Hash, e.Name)
	}
	if !*yes {
		if err := confirm("Sign them with the release key?"); err != nil {
			return err
		}
	}
	ctx, cancel := adminContext()
	defer cancel()
	pub, sig, err := signRelease(ctx, spec, sums)
	if err != nil {
		return err
	}
	if haveSigners {
		s, err := release.Verify(sums, sig, signers)
		if err != nil {
			return fmt.Errorf("not written: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Good %q signature by %s, key %s\n", release.Namespace, strings.Join(s.Principals, ","), sshsig.Fingerprint(pub))
	} else {
		fmt.Fprintf(os.Stderr, "Signed with %s; not checked against release-signers (give -signers or set release_signers)\n", sshsig.Fingerprint(pub))
	}
	if err := os.WriteFile(sigPath, sig, 0o644); err != nil { //nolint:gosec // a signature, public
		return err
	}
	fmt.Fprintf(os.Stderr, "Wrote %s\n", sigPath)
	return nil
}

// signRelease signs with the key spec names: through the SSH agent if it
// holds the key, otherwise with the private key file.
func signRelease(ctx context.Context, spec string, message []byte) (ssh.PublicKey, []byte, error) {
	var pub ssh.PublicKey
	private := ""
	if p, err := sshsig.ParseAuthorizedKey(spec); err == nil {
		pub = p
	} else {
		path := admin.ExpandHome(spec)
		data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
		if err != nil {
			return nil, nil, fmt.Errorf("release key: %w", err)
		}
		if p, err := sshsig.ParseAuthorizedKey(strings.TrimSpace(strings.TrimPrefix(string(data), "\xEF\xBB\xBF"))); err == nil {
			pub = p
			if trimmed := strings.TrimSuffix(path, ".pub"); trimmed != path {
				private = trimmed
			}
		} else {
			private = path
		}
	}
	if pub != nil {
		sig, err := admin.AgentSign(ctx, pub, release.Namespace, message)
		if err == nil {
			return pub, sig, nil
		}
		if !admin.NoAgentKey(err) || private == "" {
			return nil, nil, err
		}
		if _, serr := os.Stat(private); serr != nil {
			return nil, nil, fmt.Errorf("%w, and there is no private key file %s", err, private)
		}
		fmt.Fprintf(os.Stderr, "%v; signing with %s\n", err, private)
	}
	key, sig, err := admin.FileSign(private, func() ([]byte, error) {
		return readPassphrase("Passphrase for "+filepath.Base(private)+": ", false)
	}, release.Namespace, message)
	if err != nil {
		return nil, nil, err
	}
	if pub != nil && !bytes.Equal(key.Marshal(), pub.Marshal()) {
		return nil, nil, fmt.Errorf("private key %s does not belong to %s", private, sshsig.Fingerprint(pub))
	}
	return key, sig, nil
}

// releaseVerify implements "ergosum release verify DIR".
func releaseVerify(args []string) error {
	fs := flag.NewFlagSet("release verify", flag.ExitOnError)
	var f releaseFlags
	f.register(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: ergosum release verify [-signers FILE] DIR")
	}
	dir := fs.Arg(0)
	if fi, err := os.Stat(dir); err == nil && !fi.IsDir() {
		dir = filepath.Dir(dir)
	}
	cfg, err := f.load()
	if err != nil {
		return err
	}
	signers, ok, err := f.signerList(cfg)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("no release keys: give -signers (release-signers from the repository) or set release_signers in " + f.config)
	}
	sums, err := os.ReadFile(filepath.Join(dir, release.SumsFile)) //nolint:gosec // operator-supplied directory
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(dir, release.SigFile)) //nolint:gosec // operator-supplied directory
	if err != nil {
		return err
	}
	s, err := release.Verify(sums, sig, signers)
	if err != nil {
		return err
	}
	fmt.Printf("Good %q signature by %s, key %s\n", release.Namespace, strings.Join(s.Principals, ","), sshsig.Fingerprint(s.Key))
	entries, err := release.ParseSums(sums)
	if err != nil {
		return err
	}
	matched, missing, err := release.Check(dir, entries)
	for _, m := range matched {
		fmt.Println("OK", m)
	}
	if err != nil {
		return err
	}
	if len(matched) == 0 {
		fmt.Println("No listed file is here; only the signature was checked.")
	} else if len(missing) > 0 {
		fmt.Printf("Not here: %s\n", strings.Join(missing, ", "))
	}
	return nil
}
