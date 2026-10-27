package tlspin

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/DunkelCloud/ergosum/internal/keys"
)

func handshake(t *testing.T, server, client *tls.Config) (serverErr, clientErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		tc := tls.Server(c, server)
		err = tc.Handshake()
		if err == nil {
			_, err = tc.Write([]byte("x"))
		}
		done <- err
	}()
	c, err := tls.Dial("tcp", ln.Addr().String(), client)
	if err == nil {
		_, err = io.ReadFull(c, make([]byte, 1))
		c.Close()
	}
	return <-done, err
}

func TestMutualPinning(t *testing.T) {
	sk, _ := keys.Generate()
	ck, _ := keys.Generate()
	other, _ := keys.Generate()
	scert, _ := Certificate(sk)
	ccert, _ := Certificate(ck)
	sfp, cfp := keys.Fingerprint(&sk.PublicKey), keys.Fingerprint(&ck.PublicKey)

	if serr, cerr := handshake(t, ServerConfig(scert, Fingerprints(cfp)), ClientConfig(&ccert, Fingerprints(sfp))); serr != nil || cerr != nil {
		t.Fatalf("pinned handshake failed: %v / %v", serr, cerr)
	}
	// The client pins another server key.
	_, cerr := handshake(t, ServerConfig(scert, Fingerprints(cfp)), ClientConfig(&ccert, Fingerprints(keys.Fingerprint(&other.PublicKey))))
	if !errors.Is(cerr, ErrNotPinned) {
		t.Fatalf("unpinned server accepted: %v", cerr)
	}
	// The server pins another client key.
	serr, _ := handshake(t, ServerConfig(scert, Fingerprints(keys.Fingerprint(&other.PublicKey))), ClientConfig(&ccert, Fingerprints(sfp)))
	if !errors.Is(serr, ErrNotPinned) {
		t.Fatalf("unpinned client accepted: %v", serr)
	}
	// No client certificate at all.
	serr, _ = handshake(t, ServerConfig(scert, Fingerprints(cfp)), ClientConfig(nil, Fingerprints(sfp)))
	if serr == nil {
		t.Fatal("client without certificate accepted")
	}
}
