package e2e

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/DunkelCloud/ergosum/internal/authority"
	"github.com/DunkelCloud/ergosum/internal/daemon"
	"github.com/DunkelCloud/ergosum/internal/exchange"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

func newExchangeKey(t *testing.T) []byte {
	t.Helper()
	k, err := keys.GenerateExchangeKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func requestError(err error) *daemon.RequestError {
	var re *daemon.RequestError
	if errors.As(err, &re) {
		return re
	}
	return nil
}

func requireExchanges(t *testing.T, a *authority.Authority, result string, want float64) {
	t.Helper()
	if got := a.ExchangeCount(result); got != want {
		t.Fatalf("machine_identity_exchanges_total{result=%q} = %v, want %v", result, got, want)
	}
}

// pinAndOpen pins a share to the instance and opens it again through an
// exchange; it returns the pinned and the opened key material.
func pinAndOpen(t *testing.T, m *machine, e *env, releaseKey []byte) (pinned, opened []byte) {
	t.Helper()
	c, k, err := exchange.Pin(releaseKey)
	if err != nil {
		t.Fatal(err)
	}
	x, b, err := exchange.Blind(c, releaseKey)
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.d.Exchange(context.Background(), e.fingerprint(), [][]byte{x})
	if err != nil {
		t.Fatal(err)
	}
	opened, err = b.Unblind(r.Points[0])
	if err != nil {
		t.Fatal(err)
	}
	return k, opened
}

// TestExchange: a machine at its bound places gets its release key and has
// the instance evaluate a blinded point; it opens what it pinned. The
// exchange issues no token and writes nothing to the journal.
func TestExchange(t *testing.T) {
	xkey := newExchangeKey(t)
	e := newEnv(t, envOptions{exchangeKey: xkey})
	m := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	events := journalCount(t, e.auth, "")

	r, err := m.d.Exchange(context.Background(), e.fingerprint(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := exchange.DeriveScalar(xkey, trustDomain, host1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.Key, exchange.ReleaseKey(s)) {
		t.Fatal("the release key is not s·G for the identity")
	}
	if r.TrustDomain != trustDomain || r.Authority != e.fingerprint() || len(r.Points) != 0 {
		t.Fatalf("release key: %+v", r)
	}
	if !r.ReleaseKey.Verify(&e.key.PublicKey, protocol.ContextReleaseKey) {
		t.Fatal("the release key is not signed by the instance")
	}

	pinned, opened := pinAndOpen(t, m, e, r.Key)
	if !bytes.Equal(pinned, opened) {
		t.Fatal("the opened key material differs from the pinned one")
	}
	if n := m.d.CallbackCount(protocol.StatusConfirmed); n != 4 {
		t.Fatalf("%v callbacks confirmed, want two per exchange", n)
	}
	requireExchanges(t, e.auth, authority.ResultIssued, 2)
	requireCount(t, e.auth, authority.ResultIssued, 0)
	if n := journalCount(t, e.auth, ""); n != events {
		t.Fatalf("the journal grew from %d to %d events", events, n)
	}
}

// TestExchangeOtherIdentity: a machine that passes its own checks gets
// nothing out of another machine's client point; the instance evaluates
// it with the other identity's scalar.
func TestExchangeOtherIdentity(t *testing.T) {
	e := newEnv(t, envOptions{exchangeKey: newExchangeKey(t)})
	m1 := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet)}})
	e.bind(host1, m1.d.Fingerprint(), 1, tailnetCheck(host1Tailnet))
	m2 := e.machine(host2, machineOptions{targets: []string{at(host2Tailnet)}})
	e.bind(host2, m2.d.Fingerprint(), 1, tailnetCheck(host2Tailnet))

	r1, err := m1.d.Exchange(context.Background(), e.fingerprint(), nil)
	if err != nil {
		t.Fatal(err)
	}
	c, k, _ := exchange.Pin(r1.Key)
	// host2 holds a copy of host1's part A: client point and release key.
	x, b, _ := exchange.Blind(c, r1.Key)
	r2, err := m2.d.Exchange(context.Background(), e.fingerprint(), [][]byte{x})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Unblind(r2.Points[0]); err == nil && bytes.Equal(got, k) {
		t.Fatal("another identity opened the share")
	}
	if bytes.Equal(r2.Key, r1.Key) {
		t.Fatal("two identities have the same release key")
	}
}

// TestExchangeRefused: a copy away from the bound places and a revoked
// binding get nothing; the refusals leave the observations a token
// request leaves.
func TestExchangeRefused(t *testing.T) {
	e := newEnv(t, envOptions{exchangeKey: newExchangeKey(t)})
	real := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	e.bind(host1, real.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	r, err := real.d.Exchange(context.Background(), e.fingerprint(), nil)
	if err != nil {
		t.Fatal(err)
	}
	c, _, _ := exchange.Pin(r.Key)
	real.d.Close()

	// The copy answers on the overlay name, but nothing at the bound
	// public address.
	e.net.mu.Lock()
	delete(e.net.routes, at(host1IP))
	e.net.mu.Unlock()
	clone := e.machine(host1, machineOptions{stateDir: cloneState(t, real.stateDir), targets: []string{at(host1Tailnet)}})
	x, _, _ := exchange.Blind(c, r.Key)
	if _, err := clone.d.Exchange(context.Background(), e.fingerprint(), [][]byte{x}); !denied(err) {
		t.Fatalf("copy elsewhere: %v", err)
	}
	requireExchanges(t, e.auth, authority.ResultWrongLocation, 1)
	if n := journalCount(t, e.auth, "observation.wrong_location"); n != 1 {
		t.Fatalf("%d wrong_location observations, want 1", n)
	}

	e.revoke(host1, 2)
	if _, err := clone.d.Exchange(context.Background(), e.fingerprint(), [][]byte{x}); !denied(err) {
		t.Fatalf("revoked binding: %v", err)
	}
	requireExchanges(t, e.auth, authority.ResultUnknownIdentity, 1)
}

// TestExchangeNoKey: an instance without an exchange key answers
// no_exchange before any callback.
func TestExchangeNoKey(t *testing.T) {
	e := newEnv(t, envOptions{})
	m := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet)}})
	e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet))
	_, err := m.d.Exchange(context.Background(), e.fingerprint(), nil)
	if re := requestError(err); re == nil || re.Status != http.StatusNotFound || re.Code != protocol.ErrNoExchange {
		t.Fatalf("got %v", err)
	}
	if n := m.d.CallbackCount(protocol.StatusConfirmed); n != 0 {
		t.Fatalf("%v callbacks for an instance without exchange key", n)
	}
}

// TestExchangeBadPoints: points that are not compressed points on the
// curve are refused with the envelope, before any callback.
func TestExchangeBadPoints(t *testing.T) {
	e := newEnv(t, envOptions{exchangeKey: newExchangeKey(t)})
	m := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet)}})
	e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet))
	offCurve := append([]byte{2}, bytes.Repeat([]byte{0xff}, 32)...)
	for name, p := range map[string][]byte{"off curve": offCurve, "infinity": {0}} {
		_, err := m.d.Exchange(context.Background(), e.fingerprint(), [][]byte{p})
		if re := requestError(err); re == nil || re.Status != http.StatusBadRequest {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	if _, err := m.d.Exchange(context.Background(), e.fingerprint(), make([][]byte, protocol.MaxExchangePoints+1)); err == nil {
		t.Fatal("more points than allowed were sent")
	}
	if n := m.d.CallbackCount(protocol.StatusConfirmed); n != 0 {
		t.Fatalf("%v callbacks for refused points", n)
	}
}

// TestExchangeSharesLimit: exchange and token requests of an identity
// share its rate budget at an instance.
func TestExchangeSharesLimit(t *testing.T) {
	e := newEnv(t, envOptions{exchangeKey: newExchangeKey(t)})
	m := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet)}})
	e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet))
	for range 10 {
		if _, err := m.d.Exchange(context.Background(), e.fingerprint(), nil); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := m.d.Obtain(context.Background())
	if re := requestError(err); re == nil || re.Code != protocol.ErrRateLimited {
		t.Fatalf("token request after the burst of exchanges: %v", err)
	}
	requireCount(t, e.auth, authority.ResultRateLimited, 1)
}

// TestExchangeSealed: an encrypted exchange key opens with the signing
// key's passphrase; until then the instance releases nothing. One that
// does not open with it keeps the instance sealed.
func TestExchangeSealed(t *testing.T) {
	const pass = "correct horse battery staple"
	e := newEnv(t, envOptions{passphrase: pass, exchangeKey: newExchangeKey(t)})
	m := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet)}})
	if err := authority.UnsealVia(context.Background(), e.socket, []byte(pass)); err != nil {
		t.Fatal(err)
	}
	e.waitReady()
	e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet))
	if _, err := m.d.Exchange(context.Background(), e.fingerprint(), nil); err != nil {
		t.Fatal(err)
	}

	other := prepareEnv(t, envOptions{passphrase: pass, exchangeKey: newExchangeKey(t)})
	wrong, err := keys.EncryptExchangeKeyPEM(newExchangeKey(t), []byte("another passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other.cfg.ExchangeKeyFile, wrong, 0o600); err != nil {
		t.Fatal(err)
	}
	other.start()
	if err := authority.UnsealVia(context.Background(), other.socket, []byte(pass)); err == nil {
		t.Fatal("unsealed with an exchange key that does not open")
	}
	if !other.auth.Sealed() {
		t.Fatal("the instance is unsealed although its exchange key did not open")
	}
}
