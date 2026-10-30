package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DunkelCloud/ergosum/internal/authority"
	"github.com/DunkelCloud/ergosum/internal/journal"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/replication"
	"github.com/DunkelCloud/ergosum/internal/tlspin"
)

// links carries replication between instances and can cut it.
type links struct {
	mu    sync.Mutex
	names map[string]string // replication address -> instance
	cut   map[string]bool
	conns map[string][]net.Conn
}

func newLinks() *links {
	return &links{names: map[string]string{}, cut: map[string]bool{}, conns: map[string][]net.Conn{}}
}

func pairKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

func (l *links) dialer(from string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		l.mu.Lock()
		k := pairKey(from, l.names[addr])
		cut := l.cut[k]
		l.mu.Unlock()
		if cut {
			return nil, errors.New("links: partitioned")
		}
		var d net.Dialer
		c, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		l.mu.Lock()
		l.conns[k] = append(l.conns[k], c)
		l.mu.Unlock()
		return c, nil
	}
}

// partition cuts the link between a and b, including open connections.
func (l *links) partition(a, b string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := pairKey(a, b)
	l.cut[k] = true
	for _, c := range l.conns[k] {
		_ = c.Close()
	}
	l.conns[k] = nil
}

func (l *links) heal(a, b string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.cut, pairKey(a, b))
}

type clusterOptions struct {
	threshold  int
	compaction authority.CompactionConfig
	// unpushed instances are known to the others without URL: they get no
	// pushes, and compaction does not wait for them.
	unpushed []string
	// later instances are prepared but not started.
	later []string
}

type cluster struct {
	envs   map[string]*env
	links  *links
	admins *jt.Admins
}

const (
	instA = "authority-a"
	instB = "authority-b"
	instC = "authority-c"
)

func newCluster(t *testing.T, names []string, o clusterOptions) *cluster {
	t.Helper()
	c := &cluster{envs: map[string]*env{}, links: newLinks(), admins: jt.NewAdmins(t, "alice", "bob", "carol")}
	sn := newSimNet()
	ks := map[string]*ecdsa.PrivateKey{}
	addrs := map[string]string{}
	for _, n := range names {
		k, err := keys.Generate()
		if err != nil {
			t.Fatal(err)
		}
		ks[n], addrs[n] = k, freePort(t)
		c.links.names[addrs[n]] = n
	}
	for _, n := range names {
		var peers []authority.PeerConfig
		for _, m := range names {
			if m == n {
				continue
			}
			p := authority.PeerConfig{Name: m, Key: string(keys.MarshalPublicPEM(&ks[m].PublicKey))}
			if !slices.Contains(o.unpushed, m) {
				p.URL = "https://" + addrs[m]
			}
			peers = append(peers, p)
		}
		c.envs[n] = prepareEnv(t, envOptions{threshold: o.threshold, instance: n, net: sn, admins: c.admins,
			key: ks[n], peers: peers, replListen: addrs[n], links: c.links, compaction: o.compaction})
	}
	for _, n := range names {
		if !slices.Contains(o.later, n) {
			c.envs[n].start()
		}
	}
	return c
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *env) binding(identity string) *journal.Binding {
	e.t.Helper()
	b, err := e.auth.Store().Binding(context.Background(), identity)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

func (e *env) state() authority.JournalStatus {
	e.t.Helper()
	st, err := e.auth.JournalState(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

func (e *env) control(req authority.ControlRequest) json.RawMessage {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := authority.Control(ctx, e.socket, req, nil)
	if err != nil {
		e.t.Fatalf("%s: %v", req.Cmd, err)
	}
	return res
}

// converged reports whether all instances hold the same projection.
func converged(envs ...*env) bool {
	h := envs[0].state().StateHash
	for _, e := range envs[1:] {
		if e.state().StateHash != h {
			return false
		}
	}
	return true
}

// requireProjectionConsistent checks the stored projection against one
// recomputed from the remaining events and checkpoints.
func (e *env) requireProjectionConsistent() {
	e.t.Helper()
	ctx := context.Background()
	ref, err := e.auth.Store().Project(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	all, err := e.auth.Store().Bindings(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	if len(ref) != len(all) {
		e.t.Fatalf("%s: %d bindings, recomputed %d", e.cfg.Instance, len(all), len(ref))
	}
	for id, b := range all {
		if r := ref[id]; r == nil || r.Hash != b.Hash || r.Epoch != b.Epoch || r.Kind != b.Kind {
			e.t.Fatalf("%s: projection of %s differs from the recomputed one: %+v vs %+v", e.cfg.Instance, id, b, r)
		}
	}
}

// postPage sends a page to e's replication listener as instance from,
// authenticated with from's key.
func (e *env) postPage(from *env, p replication.Page) (int, replication.Ack) {
	e.t.Helper()
	cert, err := tlspin.Certificate(from.key)
	if err != nil {
		e.t.Fatal(err)
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: tlspin.ClientConfig(&cert, tlspin.Fingerprints(e.fingerprint())),
	}}
	body, _ := json.Marshal(p)
	resp, err := c.Post("https://"+e.cfg.Replication.Listen+replication.PathIngest, "application/json", bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var ack replication.Ack
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &ack)
	return resp.StatusCode, ack
}

func page(from string, events ...replication.Event) replication.Page {
	p := replication.Page{V: replication.Version, Instance: from}
	for i, e := range events {
		p.Events = append(p.Events, replication.Stored{Pos: int64(i + 1), Event: e})
	}
	p.Last = int64(len(events))
	return p
}

// bindingEvent wraps an admin-signed binding event as recorded by origin
// at seq, its position signed with key.
func bindingEvent(t *testing.T, key *ecdsa.PrivateKey, ev *journal.BindingEvent, origin string, seq int64) replication.Event {
	t.Helper()
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ev.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return signedAt(t, key, replication.Event{Origin: origin, Seq: seq, Kind: ev.Kind, Hash: h, Body: body})
}

// sealed signs a payload as an instance would and wraps it as an event
// whose position is signed with the same key.
func sealed(t *testing.T, key *ecdsa.PrivateKey, context, origin, kind string, seq int64, payload any) replication.Event {
	t.Helper()
	env, err := protocol.Seal(key, context, payload)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(env)
	raw, _ := base64.RawURLEncoding.DecodeString(env.Payload)
	sum := sha256.Sum256(raw)
	return signedAt(t, key, replication.Event{Origin: origin, Seq: seq, Kind: kind, Hash: hex.EncodeToString(sum[:]), Body: body})
}

// signedAt signs the position of e with key.
func signedAt(t *testing.T, key *ecdsa.PrivateKey, e replication.Event) replication.Event {
	t.Helper()
	sig, err := keys.Sign(key, protocol.ContextEvent, e.SigningInput())
	if err != nil {
		t.Fatal(err)
	}
	e.Sig = sig
	return e
}

func observationEvent(t *testing.T, key *ecdsa.PrivateKey, instance, origin string, seq int64) replication.Event {
	t.Helper()
	obs := authority.Observation{V: 1, Kind: "observation.issued", Instance: instance, Kid: keys.Thumbprint(&key.PublicKey),
		Identity: host1, RequestID: protocol.NewRequestID(), Time: time.Now().UTC()}
	return sealed(t, key, protocol.ContextObservation, origin, obs.Kind, seq, obs)
}

// checkpointEvent writes a checkpoint as instance origin would, with a
// correct state hash over the given bindings.
func checkpointEvent(t *testing.T, key *ecdsa.PrivateKey, origin string, seq int64, bindings ...*journal.BindingEvent) replication.Event {
	t.Helper()
	cp := journal.Checkpoint{V: 1, Type: "checkpoint", TrustDomain: trustDomain, Instance: origin,
		Kid: keys.Thumbprint(&key.PublicKey), CreatedAt: time.Now().UTC(), Coverage: map[string]int64{}, Bindings: []json.RawMessage{}}
	var lines []string
	for _, b := range bindings {
		body, _ := json.Marshal(b)
		cp.Bindings = append(cp.Bindings, body)
		h, err := b.Hash()
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, b.Identity+" "+strconv.FormatUint(b.Epoch, 10)+" "+h+"\n")
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "")))
	cp.StateHash = hex.EncodeToString(sum[:])
	return sealed(t, key, protocol.ContextCheckpoint, origin, journal.KindCheckpoint, seq, cp)
}

// TestReplicatedBindingHoldsEverywhere: an event written at one instance
// holds at all of them after replication; observations travel back.
func TestReplicatedBindingHoldsEverywhere(t *testing.T) {
	c := newCluster(t, []string{instA, instB, instC}, clusterOptions{})
	a, b, cc := c.envs[instA], c.envs[instB], c.envs[instC]
	m := cc.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	a.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	eventually(t, "binding at every instance", func() bool { return b.binding(host1) != nil && cc.binding(host1) != nil })
	if _, _, err := m.d.Obtain(context.Background()); err != nil {
		t.Fatalf("instance C does not issue for a binding written at A: %v", err)
	}
	eventually(t, "C's observation at A and B", func() bool {
		return journalCount(t, a.auth, "observation.issued") == 1 && journalCount(t, b.auth, "observation.issued") == 1
	})
	eventually(t, "same state everywhere", func() bool { return converged(a, b, cc) })
	eventually(t, "empty outboxes", func() bool {
		for _, e := range []*env{a, b, cc} {
			for _, p := range e.state().Peers {
				if p.Pending != 0 {
					return false
				}
			}
		}
		return true
	})
	if got := opsGet(t, a, "/metrics"); !strings.Contains(got, `machine_identity_journal_outbox_events{peer="authority-b"} 0`) ||
		!strings.Contains(got, `machine_identity_journal_coverage{origin="authority-c"} 1`) {
		t.Fatalf("journal metrics:\n%s", got)
	}
	var st authority.JournalStatus
	if err := json.Unmarshal([]byte(opsGet(t, a, protocol.PathJournalState)), &st); err != nil || st.StateHash != b.state().StateHash {
		t.Fatalf("state on the ops listener: %+v, %v", st, err)
	}
}

// TestIngestVerifiesBindingEvents: a binding event without valid
// signatures, below the threshold or with signatures over another epoch
// reaches no projection through ingest either; with approvals 2 it takes
// a second signature by another key.
func TestIngestVerifiesBindingEvents(t *testing.T) {
	c := newCluster(t, []string{instA, instB}, clusterOptions{threshold: 2})
	a, b := c.envs[instA], c.envs[instB]
	adm := c.admins
	fp := fingerprintOf(t)
	base := func(epoch uint64) *journal.BindingEvent {
		return jt.Set(trustDomain, host1, epoch, fp, tailnetCheck(host1Tailnet))
	}
	mallory := jt.NewAdmins(t, "mallory")
	cases := []struct {
		name string
		ev   *journal.BindingEvent
	}{
		{"unsigned", base(1)},
		{"one approval of two", adm.Sign(t, base(1), "alice")},
		{"one admin twice", adm.Sign(t, base(1), "alice", "alice")},
		{"signatures over different epochs", adm.SignAs(t, adm.Sign(t, base(2), "alice"), base(1), "bob")},
		{"unknown admin", mallory.Sign(t, adm.Sign(t, base(1), "alice"), "mallory")},
		{"other trust domain", adm.Sign(t, jt.Set("other.example.com", host1, 1, fp, tailnetCheck(host1Tailnet)), "alice", "bob")},
	}
	for _, tc := range cases {
		status, ack := b.postPage(a, page(instA, bindingEvent(t, a.key, tc.ev, instA, 1)))
		if status != http.StatusUnprocessableEntity || ack.Accepted != 0 {
			t.Fatalf("%s: %d %+v", tc.name, status, ack)
		}
		if b.binding(host1) != nil {
			t.Fatalf("%s: reached the projection", tc.name)
		}
	}
	if got := opsGet(t, b, "/metrics"); !strings.Contains(got, `machine_identity_journal_rejected_total{peer="authority-a"} 6`) {
		t.Fatalf("rejections not counted:\n%s", got)
	}
	status, ack := b.postPage(a, page(instA, bindingEvent(t, a.key, adm.Sign(t, base(1), "alice", "bob"), instA, 1)))
	if status != http.StatusOK || ack.Accepted != 1 || b.binding(host1) == nil {
		t.Fatalf("approved event: %d %+v", status, ack)
	}
}

// TestInstanceCatchesUpAfterOutage: an instance that was down receives
// what it missed from its peers' outboxes.
func TestInstanceCatchesUpAfterOutage(t *testing.T) {
	c := newCluster(t, []string{instA, instB}, clusterOptions{})
	a, b := c.envs[instA], c.envs[instB]
	b.stop()
	a.bind(host1, fingerprintOf(t), 1, tailnetCheck(host1Tailnet))
	a.bind(host2, fingerprintOf(t), 1, tailnetCheck(host2Tailnet))
	a.revoke(host2, 2)
	if p := a.state().Peers[0]; p.Pending != 3 || p.Oldest == nil {
		t.Fatalf("outbox while B is down: %+v", p)
	}
	b.start()
	eventually(t, "B caught up", func() bool { return converged(a, b) && b.binding(host2) != nil && !b.binding(host2).Active() })
}

// TestPartitionConverges: two events of the same epoch written on both
// sides of a partition end in the same state at every instance.
func TestPartitionConverges(t *testing.T) {
	c := newCluster(t, []string{instA, instB, instC}, clusterOptions{})
	a, b, cc := c.envs[instA], c.envs[instB], c.envs[instC]
	for _, p := range [][2]string{{instA, instB}, {instA, instC}} {
		c.links.partition(p[0], p[1])
	}
	a.bind(host1, fingerprintOf(t), 1, tailnetCheck(host1Tailnet))
	b.bind(host1, fingerprintOf(t), 1, tailnetCheck(host1Tailnet))
	if a.binding(host1).Hash == b.binding(host1).Hash {
		t.Fatal("both sides wrote the same event")
	}
	for _, p := range [][2]string{{instA, instB}, {instA, instC}} {
		c.links.heal(p[0], p[1])
	}
	eventually(t, "convergence", func() bool { return converged(a, b, cc) })
	winner := a.binding(host1)
	if journalCount(t, a.auth, "binding.set") != 2 || journalCount(t, cc.auth, "binding.set") != 2 {
		t.Fatal("both events must be journaled everywhere")
	}
	for _, e := range []*env{a, b, cc} {
		bodies, _ := e.auth.Store().EventBodies(context.Background(), "binding.set")
		for _, body := range bodies {
			var ev journal.BindingEvent
			_ = json.Unmarshal(body, &ev)
			if h, _ := ev.Hash(); h < winner.Hash {
				t.Fatalf("%s: winner %s, but %s is smaller", e.cfg.Instance, winner.Hash, h)
			}
		}
	}
}

// TestNewInstanceFromSync: a new instance builds its journal from its
// peers, the union of what they hold.
func TestNewInstanceFromSync(t *testing.T) {
	c := newCluster(t, []string{instA, instB, instC}, clusterOptions{unpushed: []string{instC}, later: []string{instC}})
	a, b, cc := c.envs[instA], c.envs[instB], c.envs[instC]
	a.bind(host1, fingerprintOf(t), 1, tailnetCheck(host1Tailnet))
	b.bind(host2, fingerprintOf(t), 1, tailnetCheck(host2Tailnet))
	eventually(t, "A and B converged", func() bool { return converged(a, b) && a.binding(host2) != nil })
	cc.start()
	if cc.binding(host1) != nil {
		t.Fatal("C was pushed to although no peer has its URL")
	}
	var res []replication.PullResult
	if err := json.Unmarshal(cc.control(authority.ControlRequest{Cmd: authority.CmdSync, From: []string{instA, instB}}), &res); err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || res[0].Events != 2 {
		t.Fatalf("sync result: %+v", res)
	}
	if !converged(a, b, cc) {
		t.Fatal("C differs from its peers after the sync")
	}
	cc.requireProjectionConsistent()
}

// TestIngestRejectsForeignObservations: an observation must verify with
// the instance key of its origin.
func TestIngestRejectsForeignObservations(t *testing.T) {
	c := newCluster(t, []string{instA, instB, instC}, clusterOptions{})
	a, b, cc := c.envs[instA], c.envs[instB], c.envs[instC]
	stranger, _ := keys.Generate()
	// The envelope cases carry a valid position signature of A, so that the
	// envelope itself is what fails.
	for name, ev := range map[string]replication.Event{
		"unknown key":             signedAt(t, a.key, observationEvent(t, stranger, instA, instA, 1)),
		"key of another peer":     signedAt(t, a.key, observationEvent(t, cc.key, instA, instA, 1)),
		"other instance claimed":  observationEvent(t, a.key, instC, instA, 1),
		"position signed by C":    signedAt(t, cc.key, observationEvent(t, a.key, instA, instA, 1)),
		"position signed by none": func() replication.Event { e := observationEvent(t, a.key, instA, instA, 1); e.Sig = nil; return e }(),
	} {
		if status, _ := b.postPage(a, page(instA, ev)); status != http.StatusUnprocessableEntity {
			t.Fatalf("%s: %d", name, status)
		}
	}
	if journalCount(t, b.auth, "observation.issued") != 0 {
		t.Fatal("a foreign observation was stored")
	}
	// Forwarded by C, an observation of A still verifies with A's key.
	if status, ack := b.postPage(cc, page(instC, observationEvent(t, a.key, instA, instA, 1))); status != http.StatusOK || ack.Accepted != 1 {
		t.Fatalf("forwarded observation: %d %+v", status, ack)
	}
	// The same origin and sequence number with another content conflicts.
	if status, _ := b.postPage(a, page(instA, observationEvent(t, a.key, instA, instA, 1))); status != http.StatusUnprocessableEntity {
		t.Fatalf("conflicting event: %d", status)
	}
}

// TestPeerCannotTakePositions: a peer cannot put a valid binding event
// under another instance's position (origin, seq), where the genuine event
// would then conflict everywhere and cut that instance off; it cannot raise
// another instance's sequence counter either, neither with an event under
// that instance's origin nor with the coverage of a checkpoint it pushes.
func TestPeerCannotTakePositions(t *testing.T) {
	c := newCluster(t, []string{instA, instB, instC}, clusterOptions{})
	a, b, cc := c.envs[instA], c.envs[instB], c.envs[instC]
	ctx := context.Background()
	a.bind(host1, fingerprintOf(t), 1, tailnetCheck(host1Tailnet))
	eventually(t, "binding everywhere", func() bool { return converged(a, b, cc) && cc.binding(host1) != nil })
	bodies, err := a.auth.Store().EventBodies(ctx, journal.KindBindingSet)
	if err != nil || len(bodies) != 1 {
		t.Fatal(bodies, err)
	}
	var ev journal.BindingEvent
	if err := json.Unmarshal(bodies[0], &ev); err != nil {
		t.Fatal(err)
	}
	nextA, nextC := a.state().NextSeq, cc.state().NextSeq
	for name, e := range map[string]replication.Event{
		"C's next position":           bindingEvent(t, b.key, &ev, instC, nextC),
		"A's own next position":       bindingEvent(t, b.key, &ev, instA, nextA+1),
		"A's last position":           bindingEvent(t, b.key, &ev, instA, math.MaxInt64-1),
		"C's position, A's signature": bindingEvent(t, a.key, &ev, instC, nextC),
	} {
		if status, ack := a.postPage(b, page(instB, e)); status != http.StatusUnprocessableEntity {
			t.Fatalf("%s: %d %+v", name, status, ack)
		}
	}
	// C's genuine event at that position still reaches everyone.
	cc.bind(host2, fingerprintOf(t), 1, tailnetCheck(host2Tailnet))
	eventually(t, "C's event everywhere", func() bool { return a.binding(host2) != nil && b.binding(host2) != nil })

	// B's own, validly signed checkpoint claims coverage of A and C. Pushed,
	// it is stored but its claims count for nothing; above the limit it does
	// not verify at all.
	empty := sha256.Sum256(nil)
	claim := func(seq int64, cov map[string]int64) replication.Stored {
		cp := journal.Checkpoint{V: 1, Type: "checkpoint", TrustDomain: trustDomain, Instance: instB,
			Kid: keys.Thumbprint(&b.key.PublicKey), CreatedAt: time.Now().UTC(), Coverage: cov,
			Bindings: []json.RawMessage{}, StateHash: hex.EncodeToString(empty[:])}
		return replication.Stored{Pos: 1, Event: sealed(t, b.key, protocol.ContextCheckpoint, instB, journal.KindCheckpoint, seq, cp)}
	}
	before := a.state()
	p := page(instB)
	start := claim(1_000_000, map[string]int64{instA: 1000, instC: 1000})
	p.Start, p.Last = &start, 1
	if status, ack := a.postPage(b, p); status != http.StatusOK {
		t.Fatalf("pushed checkpoint: %d %+v", status, ack)
	}
	if after := a.state(); after.NextSeq != before.NextSeq || after.Coverage[instC] != before.Coverage[instC] {
		t.Fatalf("a pushed checkpoint moved the counters: %+v -> %+v", before, after)
	}
	start = claim(1_000_001, map[string]int64{instC: replication.MaxSeq + 1})
	p.Start = &start
	if status, _ := a.postPage(b, p); status != http.StatusUnprocessableEntity {
		t.Fatalf("checkpoint with coverage above the limit: %d", status)
	}
	// A still writes, and its events still replicate.
	const host3, host3Tailnet = "host3.example.com", "host3.tailnet.example.com"
	a.bind(host3, fingerprintOf(t), 1, tailnetCheck(host3Tailnet))
	eventually(t, "A's new event at C", func() bool { return cc.binding(host3) != nil })
}

// TestCheckpointWithUnapprovedBindingRejected: the instance signature on a
// checkpoint grants nothing; one unapproved binding rejects all of it.
func TestCheckpointWithUnapprovedBindingRejected(t *testing.T) {
	c := newCluster(t, []string{instA, instB}, clusterOptions{})
	a, b := c.envs[instA], c.envs[instB]
	good := c.admins.Sign(t, jt.Set(trustDomain, host1, 1, fingerprintOf(t), tailnetCheck(host1Tailnet)), "alice")
	forged := jt.Set(trustDomain, host2, 1, fingerprintOf(t), tailnetCheck(host2Tailnet))
	if status, _ := b.postPage(a, page(instA, checkpointEvent(t, a.key, instA, 1, good, forged))); status != http.StatusUnprocessableEntity {
		t.Fatalf("checkpoint with an unapproved binding: %d", status)
	}
	if status, _ := b.postPage(a, page(instA, signedAt(t, a.key, checkpointEvent(t, b.key, instA, 1, good)))); status != http.StatusUnprocessableEntity {
		t.Fatalf("checkpoint of A signed with B's key: %d", status)
	}
	tampered := checkpointEvent(t, a.key, instA, 1, good)
	tampered.Hash = strings.Repeat("0", 64)
	if status, _ := b.postPage(a, page(instA, signedAt(t, a.key, tampered))); status != http.StatusUnprocessableEntity {
		t.Fatalf("checkpoint with a wrong hash: %d", status)
	}
	if b.binding(host1) != nil || b.binding(host2) != nil {
		t.Fatal("a rejected checkpoint reached the projection")
	}
	if status, _ := b.postPage(a, page(instA, checkpointEvent(t, a.key, instA, 1, good))); status != http.StatusOK || b.binding(host1) == nil {
		t.Fatalf("valid checkpoint: %d", status)
	}
}

// TestCheckpointMissingRevocation: a checkpoint written without a
// revocation does not make the revoked binding valid again.
func TestCheckpointMissingRevocation(t *testing.T) {
	c := newCluster(t, []string{instA, instB}, clusterOptions{})
	a, b := c.envs[instA], c.envs[instB]
	a.bind(host1, fingerprintOf(t), 1, tailnetCheck(host1Tailnet))
	eventually(t, "binding at B", func() bool { return b.binding(host1) != nil })
	c.links.partition(instA, instB)
	b.revoke(host1, 2)
	a.control(authority.ControlRequest{Cmd: authority.CmdCheckpoint})
	c.links.heal(instA, instB)
	eventually(t, "convergence", func() bool { return converged(a, b) && journalCount(t, b.auth, journal.KindCheckpoint) == 1 })
	for _, e := range []*env{a, b} {
		if bd := e.binding(host1); bd.Active() || bd.Epoch != 2 {
			t.Fatalf("%s: %+v", e.cfg.Instance, bd)
		}
	}
}

// TestCompaction covers the compaction rules end to end: nothing goes
// before every peer acknowledged the checkpoint; afterwards the projection
// is unchanged, sequence numbers continue, a peer cannot push deleted
// observations back, the archive holds what was deleted, and a new
// instance still builds from a sync.
func TestCompaction(t *testing.T) {
	archive := t.TempDir()
	tiny := time.Nanosecond
	c := newCluster(t, []string{instA, instB, instC}, clusterOptions{
		unpushed: []string{instC}, later: []string{instC},
		compaction: authority.CompactionConfig{
			Retention: authority.RetentionConfig{Observations: &tiny, Bindings: tiny},
			Archive:   archive,
		},
	})
	a, b, cc := c.envs[instA], c.envs[instB], c.envs[instC]
	ctx := context.Background()

	m := a.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	a.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	a.bind(host2, fingerprintOf(t), 1, tailnetCheck(host2Tailnet))
	a.bind(host2, fingerprintOf(t), 2, tailnetCheck(host2Tailnet)) // supersedes epoch 1
	eventually(t, "B has everything", func() bool { return converged(a, b) && a.state().Peers[0].Pending == 0 })

	// B is down: it cannot acknowledge the checkpoint, so nothing goes.
	b.stop()
	a.control(authority.ControlRequest{Cmd: authority.CmdCheckpoint})
	var res authority.CompactResult
	if err := json.Unmarshal(a.control(authority.ControlRequest{Cmd: authority.CmdCompact}), &res); err != nil {
		t.Fatal(err)
	}
	if res.Deleted != 0 || res.Checkpoint != 0 {
		t.Fatalf("compaction without B's acknowledgment: %+v", res)
	}
	before := a.state()

	// What compaction is about to delete, as a peer that still holds it
	// would push it back.
	_, evs, _, err := a.auth.Store().Read(ctx, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var back []replication.Event
	for _, e := range evs {
		if e.Origin == instA && e.Kind == "observation.issued" {
			back = append(back, e.Event)
		}
	}

	b.start()
	eventually(t, "B acknowledged the checkpoint", func() bool { return a.state().Peers[0].Pending == 0 })
	if err := json.Unmarshal(a.control(authority.ControlRequest{Cmd: authority.CmdCompact}), &res); err != nil {
		t.Fatal(err)
	}
	if res.Deleted == 0 || res.Checkpoint == 0 || res.Frontier[instA] == 0 {
		t.Fatalf("compaction after the acknowledgment: %+v", res)
	}
	after := a.state()
	if after.StateHash != before.StateHash || after.Bindings != 3-1 {
		t.Fatalf("projection changed by compaction: %+v -> %+v", before, after)
	}
	a.requireProjectionConsistent()
	if journalCount(t, a.auth, "observation.issued") != 0 || journalCount(t, a.auth, "binding.set") != 0 {
		t.Fatal("covered events are still there")
	}
	archived := 0
	files, _ := filepath.Glob(filepath.Join(archive, "*.jsonl"))
	for _, f := range files {
		data, _ := os.ReadFile(f)
		archived += strings.Count(string(data), "\n")
	}
	if int64(archived) < res.Deleted {
		t.Fatalf("archive holds %d events, %d were deleted", archived, res.Deleted)
	}

	// The next sequence number continues where it was.
	if _, _, err := m.d.Obtain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := a.state().NextSeq; got != after.NextSeq+1 {
		t.Fatalf("next sequence number %d, want %d", got, after.NextSeq+1)
	}
	if hash, found, _ := a.auth.Store().Lookup(ctx, instA, after.NextSeq); !found || hash == "" {
		t.Fatal("the new observation did not get the next sequence number")
	}

	// A peer cannot push the deleted observation back.
	if len(back) == 0 {
		t.Fatal("no observation of A to push back")
	}
	if status, ack := a.postPage(b, page(instB, back...)); status != http.StatusOK || ack.Accepted != int64(len(back)) {
		t.Fatalf("push back: %d %+v", status, ack)
	}
	for _, e := range back {
		if _, found, _ := a.auth.Store().Lookup(ctx, e.Origin, e.Seq); found {
			t.Fatalf("deleted observation %d came back", e.Seq)
		}
	}

	// A new instance builds from a sync after compaction.
	cc.start()
	var pulls []replication.PullResult
	if err := json.Unmarshal(cc.control(authority.ControlRequest{Cmd: authority.CmdSync, From: []string{instA}}), &pulls); err != nil {
		t.Fatal(err)
	}
	if len(pulls) != 1 || !pulls[0].Checkpoint {
		t.Fatalf("sync after compaction did not start with the checkpoint: %+v", pulls)
	}
	if !converged(a, cc) || cc.binding(host2).Epoch != 2 {
		t.Fatal("C differs from A after the sync")
	}
	cc.requireProjectionConsistent()
}

// TestExportStreamsJournal: the control socket streams the whole journal.
func TestExportStreamsJournal(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.bind(host1, fingerprintOf(t), 1, tailnetCheck(host1Tailnet))
	e.revoke(host1, 2)
	var lines []journal.ArchiveLine
	_, err := authority.Control(context.Background(), e.socket, authority.ControlRequest{Cmd: authority.CmdExport},
		func(l journal.ArchiveLine) error { lines = append(lines, l); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[1].Kind != journal.KindBindingRevoked || lines[1].Seq != 2 {
		t.Fatalf("export: %+v", lines)
	}
	var ev journal.BindingEvent
	if err := json.Unmarshal(lines[0].Body, &ev); err != nil || len(ev.Signatures) == 0 {
		t.Fatalf("exported body is not the signed event: %v", err)
	}
	for _, l := range lines {
		pos := replication.Event{Origin: l.Origin, Seq: l.Seq, Kind: l.Kind, Hash: l.Hash}
		if !keys.Verify(&e.key.PublicKey, protocol.ContextEvent, pos.SigningInput(), l.Sig) {
			t.Fatalf("exported position %s/%d is not signed by its instance", l.Origin, l.Seq)
		}
	}
}

func fingerprintOf(t *testing.T) string {
	t.Helper()
	k, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return keys.Fingerprint(&k.PublicKey)
}

// TestRefusalsReplicate: every observation kind an instance journals
// reaches the others; an unknown kind would stop replication from it.
func TestRefusalsReplicate(t *testing.T) {
	c := newCluster(t, []string{instA, instB}, clusterOptions{})
	a, b := c.envs[instA], c.envs[instB]
	m := a.machine(host1, machineOptions{targets: []string{at(host1Tailnet), at(host1IP)}})
	a.bind(host1, m.d.Fingerprint(), 1, tailnetCheck(host1Tailnet), ipCheck(host1IP))
	key, _, err := keys.LoadOrCreate(filepath.Join(m.stateDir, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	if status := postRequestTo(t, a, key, host1, protocol.NewRequestID(), b.fingerprint()); status != http.StatusForbidden {
		t.Fatalf("misdirected request: status %d", status)
	}
	eventually(t, "misdirected observation at B", func() bool {
		return journalCount(t, b.auth, "observation.misdirected") == 1
	})
	// Nothing stays behind in A's outbox: B took every event.
	eventually(t, "A's outbox empty", func() bool { return a.state().Peers[0].Pending == 0 })
}
