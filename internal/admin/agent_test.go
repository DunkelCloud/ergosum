package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/sshsig"
)

// serveKeyring answers each dial with an agent that holds the keys.
func serveKeyring(t *testing.T, held ...any) func(context.Context) (io.ReadWriteCloser, error) {
	t.Helper()
	kr := agent.NewKeyring()
	for _, k := range held {
		if err := kr.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	return func(context.Context) (io.ReadWriteCloser, error) {
		c1, c2 := net.Pipe()
		go func() { _ = agent.ServeAgent(kr, c2); _ = c2.Close() }()
		return c1, nil
	}
}

// The agent signs with the configured key among several; RSA keys sign with
// SHA-512, and a key the agent lacks is named.
func TestAgentSign(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	ctx := context.Background()
	dial := serveKeyring(t, ed, rk)
	text := []byte("ergosum binding v1\nkind binding.revoked\n")
	for _, k := range []any{ed, rk} {
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := agentSign(ctx, dial, s.PublicKey(), text)
		if err != nil {
			t.Fatalf("%s: %v", s.PublicKey().Type(), err)
		}
		pub, err := sshsig.Verify(sig, journal.Namespace, text)
		if err != nil || sshsig.Fingerprint(pub) != sshsig.Fingerprint(s.PublicKey()) {
			t.Fatalf("%s: %v", s.PublicKey().Type(), err)
		}
	}
	otherSigner, _ := ssh.NewSignerFromKey(other)
	_, err = agentSign(ctx, dial, otherSigner.PublicKey(), text)
	var na *errNoAgentKey
	if !errors.As(err, &na) {
		t.Fatalf("key not in the agent: %v", err)
	}
	_, err = agentSign(ctx, func(context.Context) (io.ReadWriteCloser, error) { return nil, errors.New("no agent") }, otherSigner.PublicKey(), text)
	if !errors.As(err, &na) {
		t.Fatalf("no agent: %v", err)
	}
}
