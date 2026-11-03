package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ergosum/internal/authority"
	"github.com/DunkelCloud/ergosum/internal/daemon"
	"github.com/DunkelCloud/ergosum/internal/journal"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/jwt"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// Places used throughout: an overlay name, a public underlay address and a
// directly attached segment.
const (
	host1        = "host1.example.com"
	host1Tailnet = "host1.tailnet.example.com"
	host1IP      = "192.0.2.10"
	host2        = "host2.example.com"
	host2Tailnet = "host2.tailnet.example.com"
	segment      = "198.51.100.0/24"
	host2Addr    = "198.51.100.20"
)

func tailnetCheck(name string) journal.Check {
	return journal.Check{Type: protocol.CheckTailnet, Target: name}
}

func ipCheck(addr string) journal.Check { return journal.Check{Type: protocol.CheckIP, Target: addr} }

func netCheck(prefix string) journal.Check {
	return journal.Check{Type: protocol.CheckNet, Target: prefix}
}

func at(host string) string { return host + ":7433" }

// TestIssuance: a machine at its bound places receives a token whose claims
// follow the JWT-SVID layout, for an ip binding and for a net binding.
func TestIssuance(t *testing.T) {
	e := newEnv(t, envOptions{networks: []string{segment}})

	m1 := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	e.bind(host1, m1.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	token, claims, err := m1.d.Obtain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, verified, err := jwt.Verify(token, func(kid string) *ecdsa.PublicKey {
		if kid == e.auth.Kid() {
			return e.auth.PublicKey()
		}
		return nil
	}, time.Now())
	if err != nil {
		t.Fatalf("token does not verify with the published key: %v", err)
	}
	if verified.Subject != "spiffe://example.com/host/"+host1 || verified.Host != host1 ||
		len(verified.Audience) != 1 || verified.Audience[0] != "vault" ||
		verified.Issuer != "https://ergosum.example.com" || verified.ID == "" {
		t.Fatalf("claims %+v", verified)
	}
	if strings.Join(claims.Checks, ",") != "ip,key,tailnet" {
		t.Fatalf("checks %v", claims.Checks)
	}
	if claims.Lifetime() != 30*time.Minute {
		t.Fatalf("lifetime %s", claims.Lifetime())
	}

	m2 := e.machine(host2, machineOptions{targets: []string{at(host2Tailnet), at(host2Addr)}, addresses: []string{"203.0.113.9", host2Addr}})
	e.bind(host2, m2.d.Fingerprint(), 1, tailnetCheck(host2Tailnet), netCheck(segment))
	if _, claims, err = m2.d.Obtain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(claims.Checks, ",") != "key,net,tailnet" {
		t.Fatalf("checks %v", claims.Checks)
	}
	requireCount(t, e.auth, authority.ResultIssued, 2)
	if n := journalCount(t, e.auth, "observation.issued"); n != 2 {
		t.Fatalf("issued observations: %d", n)
	}
}

// TestForeignKey: a request for a bound identity with another key fails at
// the signature check, without a single callback (scenario 1).
func TestForeignKey(t *testing.T) {
	e := newEnv(t, envOptions{})
	real := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	e.bind(host1, real.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))

	impostor := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	if _, _, err := impostor.d.Obtain(context.Background()); !denied(err) {
		t.Fatalf("got %v", err)
	}
	requireCount(t, e.auth, authority.ResultForeignKey, 1)
	requireCount(t, e.auth, authority.ResultIssued, 0)
	if len(e.net.dials) != 0 {
		t.Fatalf("callbacks for a foreign key: %v", e.net.dials)
	}
}

// TestUnknownIdentity: no token for an identity without binding or with a
// revoked binding.
func TestUnknownIdentity(t *testing.T) {
	e := newEnv(t, envOptions{})
	m := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	if _, _, err := m.d.Obtain(context.Background()); !denied(err) {
		t.Fatalf("unbound: %v", err)
	}
	requireCount(t, e.auth, authority.ResultUnknownIdentity, 1)

	e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	if _, _, err := m.d.Obtain(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.revoke(host1, 2)
	if _, _, err := m.d.Obtain(context.Background()); !denied(err) {
		t.Fatalf("revoked: %v", err)
	}
	requireCount(t, e.auth, authority.ResultUnknownIdentity, 2)
	requireCount(t, e.auth, authority.ResultIssued, 1)
}

// TestWrongLocation: a copy of the machine (key and overlay state) on
// foreign infrastructure reaches the overlay check but not the underlay
// (scenarios 3 and 4).
func TestWrongLocation(t *testing.T) {
	e := newEnv(t, envOptions{networks: []string{segment}})

	t.Run("ip", func(t *testing.T) {
		real := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
		e.bind(host1, real.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
		real.d.Close()
		// The original is switched off; the clone answers on the overlay
		// name, but nothing answers at the bound public address.
		e.net.mu.Lock()
		delete(e.net.routes, at(host1IP))
		e.net.mu.Unlock()
		clone := e.machine(host1, machineOptions{stateDir: cloneState(t, real.stateDir), targets: []string{at(host1Tailnet)}})
		if _, _, err := clone.d.Obtain(context.Background()); !denied(err) {
			t.Fatalf("got %v", err)
		}
		requireCount(t, e.auth, authority.ResultWrongLocation, 1)
	})

	t.Run("net", func(t *testing.T) {
		real := e.machine(host2, machineOptions{targets: []string{at(host2Tailnet), at(host2Addr)}, addresses: []string{host2Addr}})
		e.bind(host2, real.d.Fingerprint(), 1, tailnetCheck(host2Tailnet), netCheck(segment))
		// The clone gets an address outside the permitted segment.
		clone := e.machine(host2, machineOptions{stateDir: cloneState(t, real.stateDir), targets: []string{at(host2Tailnet), at("203.0.113.40")}, addresses: []string{"203.0.113.40"}})
		if _, _, err := clone.d.Obtain(context.Background()); !denied(err) {
			t.Fatalf("got %v", err)
		}
		requireCount(t, e.auth, authority.ResultWrongLocation, 2)
	})

	t.Run("other key at the bound place", func(t *testing.T) {
		const host3, host3IP = "host3.example.com", "192.0.2.30"
		owner := e.machine(host3, machineOptions{targets: []string{at(host3IP)}})
		e.bind(host3, owner.d.Fingerprint(), 1, ipCheck(host3IP))
		// The address now belongs to an unrelated machine with its own key;
		// it holds a listener open (it has a request of its own).
		other := e.machine("other.example.com", machineOptions{targets: []string{at(host3IP)}})
		release, err := other.d.HoldCallbackListener()
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		// The owner itself asks from elsewhere.
		owner.d.Close()
		thief := e.machine(host3, machineOptions{stateDir: cloneState(t, owner.stateDir), targets: []string{at("203.0.113.50")}})
		if _, _, err := thief.d.Obtain(context.Background()); !denied(err) {
			t.Fatalf("got %v", err)
		}
		requireCount(t, e.auth, authority.ResultWrongLocation, 3)
	})
	requireCount(t, e.auth, authority.ResultIssued, 0)
}

// TestRelaySignedNegative: a request with a copied key while the real
// machine is up. The callback reaches the real machine, which signs "no open
// request": no token, and the journal holds the proof (scenario 6).
func TestRelaySignedNegative(t *testing.T) {
	e := newEnv(t, envOptions{})
	real := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	e.bind(host1, real.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	// The real machine is in the middle of its own renewal.
	release, err := real.d.HoldCallbackListener()
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	// The attacker has key and overlay state and sits elsewhere; the
	// overlay name resolves to the attacker, the public address does not.
	thief := e.machine(host1, machineOptions{stateDir: cloneState(t, real.stateDir), targets: []string{at("203.0.113.66")}})
	e.net.mu.Lock()
	realAddr := e.net.routes[at(host1IP)]
	e.net.mu.Unlock()
	relRelease, err := thief.d.HoldCallbackListener()
	if err != nil {
		t.Fatal(err)
	}
	defer relRelease()
	e.net.mu.Lock()
	e.net.routes[at(host1Tailnet)] = e.net.routes[at("203.0.113.66")]
	e.net.routes[at(host1IP)] = realAddr
	e.net.mu.Unlock()

	if _, _, err := thief.d.Obtain(context.Background()); !denied(err) {
		t.Fatalf("got %v", err)
	}
	requireCount(t, e.auth, authority.ResultKeyDuplicate, 1)
	requireCount(t, e.auth, authority.ResultIssued, 0)
	if got := real.d.CallbackCount(protocol.StatusNoOpenRequest); got != 1 {
		t.Fatalf("real machine signed %v negative answers, want 1", got)
	}
	if n := journalCount(t, e.auth, "observation.key_duplicate"); n != 1 {
		t.Fatalf("key_duplicate observations: %d", n)
	}
	verifyEvidence(t, e, real.d.Fingerprint())
}

// verifyEvidence checks that the journal holds the real machine's signed
// negative answer, verifiable with the bound key alone.
func verifyEvidence(t *testing.T, e *env, fingerprint string) {
	t.Helper()
	obs := e.observations(t, "observation.key_duplicate")
	if len(obs) != 1 {
		t.Fatalf("observations: %d", len(obs))
	}
	var found bool
	for _, c := range obs[0].Checks {
		if c.Evidence == nil {
			continue
		}
		var cr protocol.CallbackResponse
		if err := c.Evidence.Decode(&cr); err != nil {
			t.Fatal(err)
		}
		if cr.Status != protocol.StatusNoOpenRequest {
			t.Fatalf("evidence status %q", cr.Status)
		}
		found = true
	}
	if !found {
		t.Fatal("no evidence in the observation")
	}
	if obs[0].Key != fingerprint {
		t.Fatalf("observation key %s", obs[0].Key)
	}
}

// TestRestartWithoutNegative: the daemon dies with a request in flight and
// comes back. The instance notices that the requester is gone, cancels the
// callbacks and discards the request without a finding; the restarted daemon
// obtains a token with a new request. No negative answer, no observation.
func TestRestartWithoutNegative(t *testing.T) {
	e := newEnv(t, envOptions{})
	targets := []string{at(host1Tailnet), at(host1IP)}
	first := e.machine(host1, machineOptions{targets: targets})
	e.bind(host1, first.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))

	// The authority holds the callbacks back; the daemon dies meanwhile.
	e.net.mu.Lock()
	e.net.gate = make(chan struct{})
	e.net.dialed = make(chan string, 4)
	e.net.aborted = make(chan string, 4)
	gate, aborted := e.net.gate, e.net.aborted
	e.net.mu.Unlock()
	ctx, crash := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, _, err := first.d.Obtain(ctx); errc <- err }()
	select {
	case <-e.net.dialed:
	case <-time.After(10 * time.Second):
		t.Fatal("authority did not start its callbacks")
	}
	crash()
	if err := <-errc; err == nil {
		t.Fatal("crashed request succeeded")
	}
	first.d.Close()
	select {
	case <-aborted:
	case <-time.After(10 * time.Second):
		t.Fatal("authority kept calling back after the requester was gone")
	}

	e.net.mu.Lock()
	close(gate)
	e.net.gate, e.net.dialed, e.net.aborted = nil, nil, nil
	e.net.mu.Unlock()

	// Restart with the same state directory.
	second := e.machine(host1, machineOptions{stateDir: first.stateDir, targets: targets})
	if second.d.Fingerprint() != first.d.Fingerprint() {
		t.Fatal("key changed across restart")
	}
	if _, _, err := second.d.Obtain(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireCount(t, e.auth, authority.ResultIssued, 1)
	for _, r := range []string{authority.ResultKeyDuplicate, authority.ResultWrongLocation, authority.ResultReplay} {
		requireCount(t, e.auth, r, 0)
	}
	if got := second.d.CallbackCount(protocol.StatusNoOpenRequest); got != 0 {
		t.Fatalf("negative answers after restart: %v", got)
	}
	if n := journalCount(t, e.auth, ""); n != 2 {
		t.Fatalf("journal holds %d events, want the binding and one issuance", n)
	}
}

// TestReplayedRequestID: a clone with the key and a request ID the real
// machine has used gets no token, even while the real machine is renewing.
// The instance that processed the ID refuses the repeat without a callback;
// at another instance the real machine does not confirm an ID that is not in
// flight to that instance, and the journal holds the proof.
func TestReplayedRequestID(t *testing.T) {
	sim := newSimNet()
	admins := jt.NewAdmins(t, "alice", "bob", "carol")
	a := newEnv(t, envOptions{instance: "authority-a", net: sim, admins: admins})
	b := newEnv(t, envOptions{instance: "authority-b", net: sim, admins: admins})
	real := a.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}, authorities: []*env{a, b}})
	a.bind(host1, real.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	b.bind(host1, real.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	if _, _, err := real.d.Obtain(context.Background()); err != nil {
		t.Fatal(err)
	}
	issued := a.observations(t, "observation.issued")
	if len(issued) != 1 {
		t.Fatalf("issued observations: %d", len(issued))
	}
	usedID := issued[0].RequestID

	release, err := real.d.HoldCallbackListener()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	stolen, _, err := keys.LoadOrCreate(filepath.Join(cloneState(t, real.stateDir), "identity.key"))
	if err != nil {
		t.Fatal(err)
	}

	sim.mu.Lock()
	before := len(sim.dials)
	sim.mu.Unlock()
	if status := postRequest(t, a, stolen, host1, usedID); status != http.StatusForbidden {
		t.Fatalf("replay at the same instance: status %d", status)
	}
	requireCount(t, a.auth, authority.ResultReplay, 1)
	sim.mu.Lock()
	after := len(sim.dials)
	sim.mu.Unlock()
	if after != before {
		t.Fatal("callbacks for a replayed request ID")
	}

	if status := postRequest(t, b, stolen, host1, usedID); status != http.StatusForbidden {
		t.Fatalf("replay at another instance: status %d", status)
	}
	requireCount(t, b.auth, authority.ResultKeyDuplicate, 1)
	requireCount(t, b.auth, authority.ResultIssued, 0)
	verifyEvidence(t, b, real.d.Fingerprint())
}

// TestForwardedRequest: an instance that forwards a request it received to
// another instance gets nothing there. The request names the instance it is
// addressed to, so the other instance refuses it before any callback, and
// the machine never has to answer "no open request" for a request it made.
func TestForwardedRequest(t *testing.T) {
	sim := newSimNet()
	admins := jt.NewAdmins(t, "alice", "bob", "carol")
	a := newEnv(t, envOptions{instance: "authority-a", net: sim, admins: admins})
	b := newEnv(t, envOptions{instance: "authority-b", net: sim, admins: admins})
	real := a.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}, authorities: []*env{a, b}})
	b.bind(host1, real.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	// The request the machine has in flight to A, as A would pass it on.
	release, err := real.d.HoldCallbackListener()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	key, _, err := keys.LoadOrCreate(filepath.Join(real.stateDir, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	sim.mu.Lock()
	before := len(sim.dials)
	sim.mu.Unlock()
	if status := postRequestTo(t, b, key, host1, protocol.NewRequestID(), a.fingerprint()); status != http.StatusForbidden {
		t.Fatalf("forwarded request: status %d", status)
	}
	sim.mu.Lock()
	after := len(sim.dials)
	sim.mu.Unlock()
	if after != before {
		t.Fatal("callbacks for a request addressed to another instance")
	}
	requireCount(t, b.auth, authority.ResultMisdirected, 1)
	requireCount(t, b.auth, authority.ResultKeyDuplicate, 0)
	if n := len(b.observations(t, "observation.misdirected")); n != 1 {
		t.Fatalf("misdirected observations: %d", n)
	}
	if real.d.CallbackCount(protocol.StatusNoOpenRequest) != 0 {
		t.Fatal("the machine answered no open request")
	}
}

// TestUnverifiedRefusalsStayOutOfJournal: requests that do not verify
// against a bound key can be sent by anyone. They count in the metric but
// never reach the journal, however many identities they name.
func TestUnverifiedRefusalsStayOutOfJournal(t *testing.T) {
	e := newEnv(t, envOptions{})
	real := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	e.bind(host1, real.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	stranger, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	const unknown, foreign = 200, 20
	for i := 0; i < unknown; i++ {
		if status := postRequest(t, e, stranger, fmt.Sprintf("host-%d.example.com", i), protocol.NewRequestID()); status != http.StatusForbidden {
			t.Fatalf("unknown identity: status %d", status)
		}
	}
	for i := 0; i < foreign; i++ {
		if status := postRequest(t, e, stranger, host1, protocol.NewRequestID()); status != http.StatusForbidden {
			t.Fatalf("foreign key: status %d", status)
		}
	}
	requireCount(t, e.auth, authority.ResultUnknownIdentity, unknown)
	requireCount(t, e.auth, authority.ResultForeignKey, foreign)
	if n := journalCount(t, e.auth, ""); n != 1 {
		t.Fatalf("journal holds %d events, want only the binding", n)
	}
}

// TestRequestsPerIdentityLimited: a copy of a bound key that sends request
// after request gets a burst of them processed, then refusals that cost no
// callback and no journal entry; the real machine's identity is the only
// one it can keep from a token.
func TestRequestsPerIdentityLimited(t *testing.T) {
	sim := newSimNet()
	e := newEnv(t, envOptions{net: sim})
	real := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet)}})
	e.bind(host1, real.d.Fingerprint(), 1, tailnetCheck(host1Tailnet))
	other := e.machine(host2, machineOptions{targets: []string{at(host2Tailnet)}})
	e.bind(host2, other.d.Fingerprint(), 1, tailnetCheck(host2Tailnet))
	release, err := real.d.HoldCallbackListener()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	copied, _, err := keys.LoadOrCreate(filepath.Join(real.stateDir, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	const sent, burst = 25, 10
	for i := range sent {
		want := http.StatusForbidden
		if i >= burst {
			want = http.StatusTooManyRequests
		}
		if status := postRequest(t, e, copied, host1, protocol.NewRequestID()); status != want {
			t.Fatalf("request %d: status %d, want %d", i+1, status, want)
		}
	}
	requireCount(t, e.auth, authority.ResultKeyDuplicate, burst)
	requireCount(t, e.auth, authority.ResultRateLimited, sent-burst)
	if n := len(e.observations(t, "observation.key_duplicate")); n != burst {
		t.Fatalf("%d key_duplicate observations, want %d", n, burst)
	}
	if n := real.d.CallbackCount(protocol.StatusNoOpenRequest); n != burst {
		t.Fatalf("%v callbacks, want %d", n, burst)
	}
	if _, _, err := other.d.Obtain(context.Background()); err != nil {
		t.Fatalf("another machine: %v", err)
	}
}

// postRequest sends a token request signed with key, as a daemon would, and
// returns the HTTP status.
func postRequest(t *testing.T, e *env, key *ecdsa.PrivateKey, identity, requestID string) int {
	t.Helper()
	return postRequestTo(t, e, key, identity, requestID, e.fingerprint())
}

// postRequestTo sends a request addressed to the instance with key
// fingerprint to, whichever instance e is.
func postRequestTo(t *testing.T, e *env, key *ecdsa.PrivateKey, identity, requestID, to string) int {
	t.Helper()
	req := protocol.TokenRequest{
		V: protocol.Version, Type: protocol.TypeTokenRequest, Identity: identity,
		RequestID: requestID, Timestamp: time.Now().UTC(),
		Key: base64.StdEncoding.EncodeToString(keys.SPKI(&key.PublicKey)), To: to,
	}
	env, err := protocol.Seal(key, protocol.ContextRequest, req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(env)
	resp, err := e.apiClient().Post(e.url+protocol.PathToken, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestRenewalRunsAllChecks: the daemon renews from half the lifetime on, and
// every renewal runs every callback again.
func TestRenewalRunsAllChecks(t *testing.T) {
	e := newEnv(t, envOptions{ttl: 10 * time.Second})
	m := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.d.Run(ctx) }()
	tokenPath := filepath.Join(m.tokenDir, "token")
	var tokens []string
	deadline := time.Now().Add(15 * time.Second)
	for len(tokens) < 2 && time.Now().Before(deadline) {
		if data, err := os.ReadFile(tokenPath); err == nil && len(data) > 0 {
			if len(tokens) == 0 || tokens[len(tokens)-1] != string(data) {
				tokens = append(tokens, string(data))
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	if len(tokens) < 2 {
		t.Fatalf("saw %d tokens, want a renewal", len(tokens))
	}
	_, c1, _ := jwt.ParseUnverified(tokens[0])
	_, c2, _ := jwt.ParseUnverified(tokens[1])
	if c1.ID == c2.ID {
		t.Fatal("renewal returned the same token")
	}
	// Renewal is scheduled 5 s ± 1 s after iat; the request itself, the loop
	// and second-granularity iat values add up to about two more seconds on
	// a loaded runner.
	elapsed := time.Duration(c2.IssuedAt-c1.IssuedAt) * time.Second
	if elapsed < 3*time.Second || elapsed > 9*time.Second {
		t.Fatalf("renewed after %s, want about half of 10s", elapsed)
	}
	issued := e.auth.RequestCount(authority.ResultIssued)
	if confirmed := m.d.CallbackCount(protocol.StatusConfirmed); confirmed != 2*issued {
		t.Fatalf("%v callbacks for %v issuances, want two per issuance", confirmed, issued)
	}
	metrics, err := os.ReadFile(filepath.Join(m.tokenDir, "ergosum.prom"))
	if err != nil || !bytes.Contains(metrics, []byte("machine_identity_token_expiry_timestamp_seconds")) {
		t.Fatalf("textfile metrics: %v %s", err, metrics)
	}
}

// TestSealed: an instance with an encrypted signing key issues nothing
// before it is unsealed through the local socket.
func TestSealed(t *testing.T) {
	e := newEnv(t, envOptions{passphrase: "correct horse battery staple"})
	if !e.auth.Sealed() {
		t.Fatal("instance with encrypted key is not sealed")
	}
	if got := opsGet(t, e, "/metrics"); !strings.Contains(got, "machine_identity_authority_sealed 1") {
		t.Fatalf("sealed metric missing:\n%s", got)
	}
	if got := opsGet(t, e, protocol.PathKeys); !strings.Contains(got, e.auth.Kid()) {
		t.Fatalf("public keys not served while sealed: %s", got)
	}
	m := e.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	if _, _, err := m.d.Obtain(context.Background()); err == nil {
		t.Fatal("token issued while sealed")
	}

	socket := e.socket
	if err := authority.UnsealVia(context.Background(), socket, []byte("wrong")); !errors.Is(err, authority.ErrUnsealFailed) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if !e.auth.Sealed() {
		t.Fatal("unsealed with a wrong passphrase")
	}
	if err := authority.UnsealVia(context.Background(), socket, []byte("correct horse battery staple")); err != nil {
		t.Fatal(err)
	}
	e.waitReady()
	if got := opsGet(t, e, "/metrics"); !strings.Contains(got, "machine_identity_authority_sealed 0") {
		t.Fatalf("sealed metric after unseal:\n%s", got)
	}
	e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	if _, _, err := m.d.Obtain(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireCount(t, e.auth, authority.ResultIssued, 1)
}

func opsGet(t *testing.T, e *env, path string) string {
	t.Helper()
	resp, err := http.Get("http://" + e.auth.OpsAddr() + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// TestBindingWriteAPI: the write API applies the registry and takes only
// events above the current epoch; nothing it rejects reaches the journal.
func TestBindingWriteAPI(t *testing.T) {
	admins := jt.NewAdmins(t, "alice", "bob", "carol")
	e := newEnv(t, envOptions{threshold: 2, admins: admins})
	k, _ := keys.Generate()
	fp := keys.Fingerprint(&k.PublicKey)
	ev := func(epoch uint64) *journal.BindingEvent {
		return jt.Set(trustDomain, host1, epoch, fp, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	}
	outsider := jt.NewAdmins(t, "mallory")
	cases := []struct {
		name   string
		event  *journal.BindingEvent
		status int
	}{
		{"no signature", ev(2), http.StatusUnprocessableEntity},
		{"invalid signature", func() *journal.BindingEvent {
			e := admins.Sign(t, ev(2), "alice", "bob")
			e.Signatures[0] = strings.Replace(e.Signatures[0], "A", "C", 2)
			return e
		}(), http.StatusUnprocessableEntity},
		{"key outside the registry", outsider.Sign(t, admins.Sign(t, ev(2), "alice"), "mallory"), http.StatusUnprocessableEntity},
		{"below threshold", admins.Sign(t, ev(2), "alice"), http.StatusUnprocessableEntity},
		{"same key twice", admins.Sign(t, ev(2), "bob", "bob"), http.StatusUnprocessableEntity},
		{"signatures over different epochs", admins.SignAs(t, admins.Sign(t, ev(2), "alice"), ev(1), "bob"), http.StatusUnprocessableEntity},
		{"valid", admins.Sign(t, ev(2), "alice", "carol"), http.StatusCreated},
		{"resubmitted", admins.Sign(t, ev(2), "bob", "carol"), http.StatusOK},
		{"lower epoch", admins.Sign(t, ev(1), "alice", "bob"), http.StatusConflict},
		{"same epoch, other event", admins.Sign(t, jt.Revoke(trustDomain, host1, 2), "alice", "bob"), http.StatusConflict},
	}
	for _, c := range cases {
		status, body := e.writeBinding(c.event)
		if status != c.status {
			t.Errorf("%s: status %d, want %d (%s)", c.name, status, c.status, body)
		}
	}
	if n := journalCount(t, e.auth, ""); n != 1 {
		t.Fatalf("journal holds %d events, want 1", n)
	}
	b, _ := e.auth.Store().Binding(context.Background(), host1)
	if b == nil || b.Epoch != 2 || b.Key != fp {
		t.Fatalf("projection %+v", b)
	}
}

// TestNetCheckNeedsAttachedNetwork: an instance without the segment answers
// "not responsible", and the daemon moves on to the instance that has it.
func TestNetCheckNeedsAttachedNetwork(t *testing.T) {
	sim := newSimNet()
	admins := jt.NewAdmins(t, "alice", "bob", "carol")
	remote := newEnv(t, envOptions{instance: "authority-remote", net: sim, admins: admins})
	local := newEnv(t, envOptions{instance: "authority-local", net: sim, admins: admins, networks: []string{segment}})
	m := remote.machine(host2, machineOptions{
		targets:     []string{at(host2Tailnet), at(host2Addr)},
		addresses:   []string{host2Addr},
		authorities: []*env{remote, local},
	})
	remote.bind(host2, m.d.Fingerprint(), 1, tailnetCheck(host2Tailnet), netCheck(segment))
	local.bind(host2, m.d.Fingerprint(), 1, tailnetCheck(host2Tailnet), netCheck(segment))
	if _, _, err := m.d.Obtain(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireCount(t, remote.auth, authority.ResultIssued, 0)
	requireCount(t, local.auth, authority.ResultIssued, 1)
}

// TestNetCheckFromAnchorOnly: a new machine that knows only an anchor
// without the segment takes the anchor's list when it answers "not
// responsible", and reaches the instance that has the segment in the same
// round. Without a list from the anchor, the round ends with "not
// responsible".
func TestNetCheckFromAnchorOnly(t *testing.T) {
	sim := newSimNet()
	admins := jt.NewAdmins(t, "alice", "bob", "carol")
	remote := prepareEnv(t, envOptions{instance: "authority-remote", net: sim, admins: admins})
	local := prepareEnv(t, envOptions{instance: "authority-local", net: sim, admins: admins, networks: []string{segment}})
	list := filepath.Join(t.TempDir(), "authorities.yaml")
	writeList(t, list, 1, listed{e: remote}, listed{e: local})
	remote.start()
	local.cfg.AuthoritiesFile = list
	local.start()
	opts := machineOptions{
		targets:     []string{at(host2Tailnet), at(host2Addr)},
		addresses:   []string{host2Addr},
		authorities: []*env{remote},
	}
	m := remote.machine(host2, opts)
	for _, e := range []*env{remote, local} {
		e.bind(host2, m.d.Fingerprint(), 1, tailnetCheck(host2Tailnet), netCheck(segment))
	}
	ctx := context.Background()

	var re *daemon.RequestError
	if _, _, err := m.d.Obtain(ctx); !errors.As(err, &re) || re.Code != protocol.ErrNotResponsible {
		t.Fatalf("anchor without a list: %v", err)
	}
	if got := storedSerial(t, m); got != 0 {
		t.Fatalf("stored serial %d without a list", got)
	}

	remote.stop()
	remote.cfg.AuthoritiesFile = list
	remote.start()
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatalf("through the anchor's list: %v", err)
	}
	requireCount(t, remote.auth, authority.ResultIssued, 0)
	requireCount(t, local.auth, authority.ResultIssued, 1)
	if got := storedSerial(t, m); got != 1 {
		t.Fatalf("stored serial %d, want the anchor's 1", got)
	}
}

// A private network and a machine's fixed address in it.
const (
	lan      = "10.99.0.0/24"
	host1LAN = "10.99.0.20"
)

// TestPrivateIPCheckNeedsAttachedNetwork: an ip check on a private address
// runs only at an instance attached to that network. Another instance would
// call another machine or nobody; it answers "not responsible" without a
// callback, and the daemon moves on to the instance that has the network.
func TestPrivateIPCheckNeedsAttachedNetwork(t *testing.T) {
	sim := newSimNet()
	admins := jt.NewAdmins(t, "alice", "bob", "carol")
	remote := newEnv(t, envOptions{instance: "authority-remote", net: sim, admins: admins})
	local := newEnv(t, envOptions{instance: "authority-local", net: sim, admins: admins, networks: []string{lan}})
	m := remote.machine(host1, machineOptions{
		targets:     []string{at(host1Tailnet), at(host1LAN)},
		addresses:   []string{host1LAN},
		authorities: []*env{remote, local},
	})
	for _, e := range []*env{remote, local} {
		e.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1LAN))
	}
	if _, _, err := m.d.Obtain(context.Background()); err != nil {
		t.Fatal(err)
	}
	requireCount(t, remote.auth, authority.ResultWrongLocation, 0)
	requireCount(t, remote.auth, authority.ResultIssued, 0)
	requireCount(t, local.auth, authority.ResultIssued, 1)
	sim.mu.Lock()
	defer sim.mu.Unlock()
	if len(sim.dials) != 2 {
		t.Fatalf("callbacks %v, want one per check from the attached instance only", sim.dials)
	}
}

// TestPrivateIPCheckCatchesCloneInNetwork: a copy of a machine inside the
// machine's own network, at another address, would pass a net check. An ip
// check on the machine's fixed address reaches the original instead, whose
// signed "no open request" proves the copy.
func TestPrivateIPCheckCatchesCloneInNetwork(t *testing.T) {
	e := newEnv(t, envOptions{networks: []string{lan}})
	real := e.machine(host1, machineOptions{targets: []string{at(host1LAN)}, addresses: []string{host1LAN}})
	e.bind(host1, real.d.Fingerprint(), 1, ipCheck(host1LAN))
	// The original is in the middle of its own renewal.
	release, err := real.d.HoldCallbackListener()
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	const cloneAddr = "10.99.0.30"
	clone := e.machine(host1, machineOptions{stateDir: cloneState(t, real.stateDir), targets: []string{at(cloneAddr)}, addresses: []string{cloneAddr}})
	if _, _, err := clone.d.Obtain(context.Background()); !denied(err) {
		t.Fatalf("got %v", err)
	}
	requireCount(t, e.auth, authority.ResultKeyDuplicate, 1)
	requireCount(t, e.auth, authority.ResultIssued, 0)
	verifyEvidence(t, e, real.d.Fingerprint())
}

// observations decodes the journal's observations of one kind.
func (e *env) observations(t *testing.T, kind string) []authority.Observation {
	t.Helper()
	bodies, err := e.auth.Store().EventBodies(context.Background(), kind)
	if err != nil {
		t.Fatal(err)
	}
	var out []authority.Observation
	for _, b := range bodies {
		var env protocol.Envelope
		if err := json.Unmarshal(b, &env); err != nil {
			t.Fatal(err)
		}
		if !env.Verify(e.auth.PublicKey(), protocol.ContextObservation) {
			t.Fatal("observation signature does not verify")
		}
		var o authority.Observation
		if err := env.Decode(&o); err != nil {
			t.Fatal(err)
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

// TestKeySwitchNeedsEveryAuthority: one authority that already shows a
// binding to the next key cannot make the daemon switch while another
// still binds the current key; the daemon keeps its key and its token.
func TestKeySwitchNeedsEveryAuthority(t *testing.T) {
	sim := newSimNet()
	admins := jt.NewAdmins(t, "alice", "bob", "carol")
	a := newEnv(t, envOptions{instance: "authority-a", net: sim, admins: admins})
	b := newEnv(t, envOptions{instance: "authority-b", net: sim, admins: admins})
	m := a.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}, authorities: []*env{a, b}})
	old := m.d.Fingerprint()
	a.bind(host1, old, 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	b.bind(host1, old, 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	next, err := m.d.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	a.bind(host1, next, 2, tailnetCheck(host1Tailnet), ipCheck(host1IP)) // only A
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.d.Run(ctx) }()
	eventually(t, "token", func() bool {
		_, err := os.Stat(filepath.Join(m.tokenDir, "token"))
		return err == nil
	})
	stop()
	<-done
	if m.d.Fingerprint() != old || m.d.PendingFingerprint() != next {
		t.Fatalf("switched on the word of one authority: current %s, next %s", m.d.Fingerprint(), m.d.PendingFingerprint())
	}
	requireCount(t, b.auth, authority.ResultIssued, 1)
}
