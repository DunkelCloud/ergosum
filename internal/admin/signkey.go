package admin

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

// SignKey is the key one administrator signs with.
type SignKey struct {
	// Public is the key, or nil if only the signature will tell (a private
	// key file whose public half cannot be read without its passphrase).
	Public ssh.PublicKey
	Sign   Signer
}

// Fingerprint returns the SSH fingerprint of the key, or "" if unknown.
func (k *SignKey) Fingerprint() string {
	if k == nil || k.Public == nil {
		return ""
	}
	return sshsig.Fingerprint(k.Public)
}

// LoadSignKey resolves the configured administrator key. spec is a public
// key line or a file: a public key (OpenSSH, or SSH2 as PuTTYgen exports
// it) is used through the SSH agent, falling back to ssh-keygen with the
// private key file next to it; a private key file is signed with ssh-keygen,
// which asks for the passphrase or the touch of a security key.
func LoadSignKey(spec, keygen string) (*SignKey, error) {
	if pub, err := sshsig.ParseAuthorizedKey(spec); err == nil {
		return &SignKey{Public: pub, Sign: AgentSigner(pub, "", keygen)}, nil
	}
	path := ExpandHome(spec)
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("sign key: %w", err)
	}
	text := strings.TrimSpace(strings.TrimPrefix(string(data), "\xEF\xBB\xBF"))
	switch {
	case strings.HasPrefix(text, "PuTTY-User-Key-File"):
		return nil, fmt.Errorf("sign key %s is a PuTTY private key: load it into Pageant and configure its public key "+
			"(PuTTYgen: the line under \"Public key for pasting into OpenSSH authorized_keys file\")", spec)
	case strings.HasPrefix(text, "---- BEGIN SSH2 PUBLIC KEY ----"):
		pub, err := parseSSH2PublicKey(text)
		if err != nil {
			return nil, fmt.Errorf("sign key %s: %w", spec, err)
		}
		return &SignKey{Public: pub, Sign: AgentSigner(pub, "", keygen)}, nil
	}
	if pub, err := sshsig.ParseAuthorizedKey(text); err == nil {
		private := strings.TrimSuffix(path, ".pub")
		if private == path {
			private = ""
		}
		return &SignKey{Public: pub, Sign: AgentSigner(pub, private, keygen)}, nil
	}
	// A private key file: ssh-keygen signs, through the agent if it holds
	// the key.
	k := &SignKey{Sign: SSHKeygen(keygen, path)}
	if pubData, err := os.ReadFile(path + ".pub"); err == nil { //nolint:gosec // next to the operator-supplied path
		k.Public, _ = sshsig.ParseAuthorizedKey(strings.TrimSpace(string(pubData)))
	}
	if k.Public == nil {
		_, err := ssh.ParseRawPrivateKey(data)
		var pme *ssh.PassphraseMissingError
		switch {
		case errors.As(err, &pme):
			k.Public = pme.PublicKey
		case err == nil:
			if s, err := ssh.ParsePrivateKey(data); err == nil {
				k.Public = s.PublicKey()
			}
		}
	}
	return k, nil
}

// parseSSH2PublicKey reads a public key in the SSH2 format (RFC 4716).
func parseSSH2PublicKey(text string) (ssh.PublicKey, error) {
	var b64 strings.Builder
	cont := false
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "---- "):
		case cont || strings.Contains(line, ":"):
			// A header, possibly continued with a trailing backslash.
			cont = strings.HasSuffix(line, `\`)
		default:
			b64.WriteString(line)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return nil, errors.New("bad SSH2 public key")
	}
	return ssh.ParsePublicKey(raw)
}

// ExpandHome replaces a leading ~ with the home directory.
func ExpandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

// errNoAgentKey: the agent is not reachable or does not hold the key.
type errNoAgentKey struct{ err error }

func (e *errNoAgentKey) Error() string { return e.err.Error() }
func (e *errNoAgentKey) Unwrap() error { return e.err }

// AgentSigner signs with the key pub held by the SSH agent: the socket in
// SSH_AUTH_SOCK, on Windows also the pipe of the OpenSSH agent service.
// If the agent does not hold the key and private names its private key
// file, ssh-keygen signs with that file instead.
func AgentSigner(pub ssh.PublicKey, private, keygen string) Signer {
	return func(ctx context.Context, canonical []byte) ([]byte, error) {
		sig, err := agentSign(ctx, dialAgent, pub, journal.Namespace, canonical)
		if NoAgentKey(err) && private != "" {
			if _, serr := os.Stat(private); serr == nil {
				return SSHKeygen(keygen, private)(ctx, canonical)
			}
		}
		return sig, err
	}
}

// AgentSign signs message in namespace with the key pub that the SSH agent
// holds. NoAgentKey tells whether no agent answered or it lacks the key.
func AgentSign(ctx context.Context, pub ssh.PublicKey, namespace string, message []byte) ([]byte, error) {
	return agentSign(ctx, dialAgent, pub, namespace, message)
}

// NoAgentKey reports whether err from AgentSign means that no agent
// answered or that it does not hold the key.
func NoAgentKey(err error) bool {
	var na *errNoAgentKey
	return errors.As(err, &na)
}

// FileSign signs message in namespace with a private key file and returns
// the public key with the signature. passphrase is asked only for an
// encrypted file. The file is read here, not by ssh-keygen, so that
// neither the ssh-keygen found first in PATH nor Windows line ends in the
// file matter. Keys on security keys need the agent.
func FileSign(file string, passphrase func() ([]byte, error), namespace string, message []byte) (ssh.PublicKey, []byte, error) {
	data, err := os.ReadFile(ExpandHome(file)) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, nil, err
	}
	key, err := ssh.ParseRawPrivateKey(data)
	var pme *ssh.PassphraseMissingError
	if errors.As(err, &pme) {
		pass, perr := passphrase()
		if perr != nil {
			return nil, nil, perr
		}
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(data, pass)
		clear(pass)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("private key %s: %w", file, err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("private key %s: %w", file, err)
	}
	sig, err := sshsig.Sign(signer, namespace, message)
	return signer.PublicKey(), sig, err
}

func agentSign(ctx context.Context, dial func(context.Context) (io.ReadWriteCloser, error), pub ssh.PublicKey, namespace string, canonical []byte) ([]byte, error) {
	conn, err := dial(ctx)
	if err != nil {
		return nil, &errNoAgentKey{fmt.Errorf("ssh-agent: %w", err)}
	}
	defer func() { _ = conn.Close() }()
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		return nil, fmt.Errorf("ssh-agent: %w", err)
	}
	want := pub.Marshal()
	for _, s := range signers {
		if bytes.Equal(s.PublicKey().Marshal(), want) {
			return sshsig.Sign(s, namespace, canonical)
		}
	}
	return nil, &errNoAgentKey{fmt.Errorf("ssh-agent does not hold the key %s; add it with ssh-add", sshsig.Fingerprint(pub))}
}
