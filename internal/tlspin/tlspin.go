// Package tlspin builds TLS 1.3 configurations in which both sides are
// identified by their long-term ECDSA P-256 keys instead of a CA: each side
// presents a self-signed certificate for its key, and the peer accepts it
// only if the key's fingerprint is pinned.
package tlspin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/DunkelCloud/ergosum/internal/keys"
)

// ServerName is sent as SNI. Names play no role in verification.
const ServerName = "ergosum"

// Certificate returns a self-signed certificate for key. Validity dates are
// not checked by peers; only the key matters.
func Certificate(key *ecdsa.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: keys.Fingerprint(&key.PublicKey)},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// Pins decides whether a peer key fingerprint (keys.Fingerprint) is allowed.
type Pins func(fingerprint string) bool

// Fingerprints returns Pins that allow exactly the given fingerprints.
func Fingerprints(fps ...string) Pins {
	set := make(map[string]bool, len(fps))
	for _, f := range fps {
		set[f] = true
	}
	return func(fp string) bool { return set[fp] }
}

// ErrNotPinned is wrapped by verification errors for unknown peer keys.
var ErrNotPinned = errors.New("tlspin: peer key not pinned")

// verifier checks the peer's leaf key against pins. It runs as
// VerifyConnection, which, unlike VerifyPeerCertificate, also runs for
// resumed sessions.
func verifier(pins Pins) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("tlspin: peer sent no certificate")
		}
		pub, err := LeafKey(cs.PeerCertificates[0].Raw)
		if err != nil {
			return err
		}
		fp := keys.Fingerprint(pub)
		if !pins(fp) {
			return fmt.Errorf("%w: %s", ErrNotPinned, fp)
		}
		return nil
	}
}

// LeafKey extracts the P-256 public key of a DER certificate.
func LeafKey(der []byte) (*ecdsa.PublicKey, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("tlspin: peer key is not ECDSA P-256")
	}
	return pub, nil
}

// PeerKey returns the verified peer key of an established connection.
func PeerKey(cs *tls.ConnectionState) (*ecdsa.PublicKey, error) {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return nil, errors.New("tlspin: no peer certificate")
	}
	return LeafKey(cs.PeerCertificates[0].Raw)
}

// ClientConfig returns a client configuration that presents cert (if not
// nil) and accepts only a server whose key is pinned.
func ClientConfig(cert *tls.Certificate, server Pins) *tls.Config {
	c := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: ServerName,
		// Chain verification is replaced by key pinning in
		// VerifyConnection; the TLS 1.3 handshake still proves possession
		// of the pinned key.
		InsecureSkipVerify: true, //nolint:gosec // see comment above
		VerifyConnection:   verifier(server),
	}
	if cert != nil {
		c.Certificates = []tls.Certificate{*cert}
	}
	return c
}

// ServerConfig returns a server configuration presenting cert. With
// client != nil, a client certificate with a pinned key is required.
func ServerConfig(cert tls.Certificate, client Pins) *tls.Config {
	c := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		// Every connection is a full handshake with the long-term keys.
		SessionTicketsDisabled: true,
	}
	if client != nil {
		c.ClientAuth = tls.RequireAnyClientCert
		c.VerifyConnection = verifier(client)
	}
	return c
}
