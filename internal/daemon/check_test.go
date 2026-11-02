package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"net"
	"strings"
	"testing"

	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// A URL presents its key or is not reached; nothing else is needed from
// it.
func TestCheckKeys(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tlspin.Certificate(key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlspin.ServerConfig(cert, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	// A port that was just free: nothing listens there.
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "https://" + free.Addr().String()
	_ = free.Close()

	fp := keys.Fingerprint(&key.PublicKey)
	other := "SHA256:" + strings.Repeat("A", 43)
	serving := "https://" + ln.Addr().String()
	cfg := Config{Authorities: []AuthorityConfig{
		{Key: fp, URLs: []string{serving, closed}},
		{Key: other, URL: serving},
	}}
	got := CheckKeys(context.Background(), cfg)
	want := []KeyCheck{
		{URL: serving, Want: fp, Got: fp},
		{URL: closed, Want: fp},
		{URL: serving, Want: other, Got: fp},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d checks, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.URL != w.URL || g.Want != w.Want || g.Got != w.Got {
			t.Errorf("check %d: got %+v, want %+v", i, g, w)
		}
		if (g.Got == "") != (g.Err != nil) {
			t.Errorf("check %d: key %q with error %v", i, g.Got, g.Err)
		}
	}
}
