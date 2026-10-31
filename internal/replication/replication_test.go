package replication_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DunkelCloud/ergosum/internal/replication"
)

// memStore is a minimal Store: events in memory, coverage as the
// contiguous prefix of each origin.
type memStore struct {
	mu        sync.Mutex
	self      string
	events    []replication.Stored
	next      int64
	cov       map[string]int64
	cursors   map[string]int64
	frontier  map[string]int64
	frontCP   *replication.Stored
	compacted int64
}

func newMemStore(self string) *memStore {
	return &memStore{self: self, next: 1, cov: map[string]int64{}, cursors: map[string]int64{}, frontier: map[string]int64{}}
}

func (s *memStore) appendLocked(e replication.Event) {
	s.events = append(s.events, replication.Stored{Pos: s.next, Event: e})
	s.next++
	if e.Seq == s.cov[e.Origin]+1 {
		s.cov[e.Origin] = e.Seq
		for s.find(e.Origin, s.cov[e.Origin]+1) != nil {
			s.cov[e.Origin]++
		}
	}
}

func (s *memStore) find(origin string, seq int64) *replication.Stored {
	for i := range s.events {
		if s.events[i].Origin == origin && s.events[i].Seq == seq {
			return &s.events[i]
		}
	}
	return nil
}

// local appends an own event.
func (s *memStore) local(kind, body string) replication.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	sum := sha256.Sum256([]byte(body))
	e := replication.Event{Origin: s.self, Seq: s.cov[s.self] + 1, Kind: kind, Hash: hex.EncodeToString(sum[:]), Body: []byte(body)}
	s.appendLocked(e)
	return e
}

func (s *memStore) Read(_ context.Context, after int64, limit int) (*replication.Stored, []replication.Stored, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var start *replication.Stored
	last := after
	if after < s.compacted {
		cp := *s.frontCP
		start = &cp
	}
	var out []replication.Stored
	for _, e := range s.events {
		if e.Pos > after && len(out) < limit {
			out = append(out, e)
			last = max(last, e.Pos)
		}
	}
	if len(out) < limit {
		last = max(last, s.compacted)
	}
	return start, out, last, nil
}

func (s *memStore) Lookup(_ context.Context, origin string, seq int64) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.find(origin, seq); e != nil {
		return e.Hash, true, nil
	}
	return "", false, nil
}

func (s *memStore) Contains(_ context.Context, kind, hash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if e.Kind == kind && e.Hash == hash {
			return true, nil
		}
	}
	return false, nil
}

func (s *memStore) Coverage(_ context.Context, origin string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cov[origin], nil
}

func (s *memStore) Append(_ context.Context, e replication.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.find(e.Origin, e.Seq) != nil {
		return errors.New("duplicate")
	}
	s.appendLocked(e)
	return nil
}

func (s *memStore) RaiseCoverage(_ context.Context, cov map[string]int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for o, n := range cov {
		s.cov[o] = max(s.cov[o], n)
		for s.find(o, s.cov[o]+1) != nil {
			s.cov[o]++
		}
	}
	return nil
}

func (s *memStore) Cursor(_ context.Context, peer string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cursors[peer], nil
}

func (s *memStore) SetCursor(_ context.Context, peer string, pos int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursors[peer] = pos
	return nil
}

func (s *memStore) Outbox(_ context.Context, after int64) (int64, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, e := range s.events {
		if e.Pos > after {
			n++
		}
	}
	return n, time.Time{}, nil
}

func (s *memStore) LatestAt(_ context.Context, origin, kind string, pos int64) (*replication.Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.events) - 1; i >= 0; i-- {
		if e := s.events[i]; e.Origin == origin && e.Kind == kind && e.Pos <= pos {
			return &e, nil
		}
	}
	return nil, nil
}

func (s *memStore) SetFrontier(_ context.Context, cp replication.Stored, frontier map[string]int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frontCP = &cp
	for o, n := range frontier {
		s.frontier[o] = max(s.frontier[o], n)
	}
	return nil
}

// compact deletes every event under the frontier except checkpoints.
func (s *memStore) compact() {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.events[:0]
	for _, e := range s.events {
		if e.Kind != kindCheckpoint && e.Seq <= s.frontier[e.Origin] {
			s.compacted = max(s.compacted, e.Pos)
			continue
		}
		kept = append(kept, e)
	}
	s.events = kept
}

func (s *memStore) has(origin string, seq int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.find(origin, seq) != nil
}

const (
	kindNote       = "note"
	kindRule       = "rule" // always ingested, like binding events
	kindCheckpoint = "checkpoint"
)

// checkpointBody is a test checkpoint: just the coverage.
func checkpointBody(cov map[string]int64) string {
	b, _ := json.Marshal(cov)
	return string(b)
}

type node struct {
	name  string
	store *memStore
	rep   *replication.Replicator
	srv   *httptest.Server
	// verify rejects bodies starting with "bad" and fails without a
	// verdict on bodies starting with "flaky".
	rejected []string
	mu       sync.Mutex
}

// cluster builds nodes whose peers are given by links (name -> peers with
// URL); every node knows every other node. opts adjust each configuration.
func cluster(t *testing.T, names []string, links map[string][]string, opts ...func(*replication.Config)) map[string]*node {
	t.Helper()
	nodes := map[string]*node{}
	for _, n := range names {
		nodes[n] = &node{name: n, store: newMemStore(n)}
		nd := nodes[n]
		nd.srv = httptest.NewUnstartedServer(nil)
	}
	for _, n := range names {
		nd := nodes[n]
		var peers []replication.Peer
		for _, o := range names {
			if o == n {
				continue
			}
			p := replication.Peer{Name: o}
			for _, l := range links[n] {
				if l == o {
					p.URL = "http://" + nodes[o].srv.Listener.Addr().String()
				}
			}
			peers = append(peers, p)
		}
		cfg := replication.Config{
			Self:  n,
			Peers: peers,
			Store: nd.store,
			Verify: func(_ context.Context, e replication.Event) error {
				switch {
				case strings.HasPrefix(string(e.Body), "bad"):
					nd.mu.Lock()
					nd.rejected = append(nd.rejected, string(e.Body))
					nd.mu.Unlock()
					return fmt.Errorf("%w: bad body", replication.ErrInvalid)
				case strings.HasPrefix(string(e.Body), "flaky"):
					return errors.New("database unavailable")
				}
				return nil
			},
			AlwaysIngest:   func(kind string) bool { return kind == kindRule },
			CheckpointKind: kindCheckpoint,
			CheckpointCoverage: func(e replication.Event) (map[string]int64, error) {
				var cov map[string]int64
				return cov, json.Unmarshal(e.Body, &cov)
			},
			Client: func(string) *http.Client {
				c := &http.Client{Timeout: 5 * time.Second, Transport: &peerHeader{name: n}}
				return c
			},
			Authenticate: func(r *http.Request) (string, bool) {
				p := r.Header.Get("X-Test-Peer")
				return p, p != ""
			},
			RetryMin: 10 * time.Millisecond,
			RetryMax: 50 * time.Millisecond,
			Idle:     20 * time.Millisecond,
		}
		for _, o := range opts {
			o(&cfg)
		}
		rep, err := replication.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		nd.rep = rep
		nd.srv.Config.Handler = rep.Handler()
		nd.srv.Start()
		t.Cleanup(nd.srv.Close)
	}
	return nodes
}

// peerHeader stands in for mutual TLS: it names the sender.
type peerHeader struct{ name string }

func (p *peerHeader) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Test-Peer", p.name)
	return http.DefaultTransport.RoundTrip(r)
}

func run(t *testing.T, nodes map[string]*node) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n.rep.Run(ctx)
		}()
	}
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPushForwardsThroughThirdInstance(t *testing.T) {
	// a - b - c: a and c are not peers, events travel through b.
	nodes := cluster(t, []string{"a", "b", "c"}, map[string][]string{"a": {"b"}, "b": {"a", "c"}, "c": {"b"}})
	run(t, nodes)
	e := nodes["a"].store.local(kindNote, "from a")
	nodes["a"].rep.Notify()
	eventually(t, "a's event at c", func() bool { return nodes["c"].store.has(e.Origin, e.Seq) })
	f := nodes["c"].store.local(kindNote, "from c")
	nodes["c"].rep.Notify()
	eventually(t, "c's event at a", func() bool { return nodes["a"].store.has(f.Origin, f.Seq) })
	eventually(t, "a's outbox empty", func() bool {
		st, _ := nodes["a"].rep.Status(context.Background())
		return len(st) == 1 && st[0].Pending == 0
	})
}

func ingest(t *testing.T, r *replication.Replicator, peer string, events ...replication.Event) (int64, error) {
	t.Helper()
	p := replication.Page{V: replication.Version, Instance: peer}
	for i, e := range events {
		p.Events = append(p.Events, replication.Stored{Pos: int64(i + 1), Event: e})
	}
	p.Last = int64(len(events))
	return r.Ingest(context.Background(), peer, p)
}

func ev(origin string, seq int64, kind, body string) replication.Event {
	sum := sha256.Sum256([]byte(body))
	return replication.Event{Origin: origin, Seq: seq, Kind: kind, Hash: hex.EncodeToString(sum[:]), Body: []byte(body)}
}

func TestIngestRules(t *testing.T) {
	nodes := cluster(t, []string{"a", "b"}, nil)
	a := nodes["a"]

	// Idempotent by origin and sequence number.
	if _, err := ingest(t, a.rep, "b", ev("b", 1, kindNote, "one"), ev("b", 1, kindNote, "one")); err != nil {
		t.Fatal(err)
	}
	// Same (origin, seq) with another hash that verifies: the origin signed
	// two events for one position. The first stays, the second is skipped,
	// and what follows still arrives.
	acc, err := ingest(t, a.rep, "b", ev("b", 2, kindNote, "two"), ev("b", 2, kindNote, "other"), ev("b", 3, kindNote, "three"))
	if err != nil || acc != 3 {
		t.Fatalf("equivocation: accepted %d, err %v", acc, err)
	}
	if h, _, _ := a.store.Lookup(context.Background(), "b", 2); h != ev("b", 2, kindNote, "two").Hash || !a.store.has("b", 3) {
		t.Fatal("equivocation changed the stored event or stopped the page")
	}
	// Same position, another hash that does not verify: rejected.
	if _, err := ingest(t, a.rep, "b", ev("b", 2, kindNote, "bad two")); !errors.Is(err, replication.ErrRejected) {
		t.Fatalf("forged conflict: %v", err)
	}
	// A rejected event stops the page; coverage stays below it.
	acc, err = ingest(t, a.rep, "b", ev("b", 3, kindNote, "three"), ev("b", 4, kindNote, "bad four"), ev("b", 5, kindNote, "five"))
	if !errors.Is(err, replication.ErrRejected) || acc != 1 {
		t.Fatalf("rejection: accepted %d, err %v", acc, err)
	}
	if c, _ := a.store.Coverage(context.Background(), "b"); c != 3 {
		t.Fatalf("coverage %d, want 3", c)
	}
	// Unknown origins are refused.
	if _, err := ingest(t, a.rep, "b", ev("x", 1, kindNote, "who")); !errors.Is(err, replication.ErrRejected) {
		t.Fatalf("unknown origin: %v", err)
	}
	// Below the coverage, ordinary kinds are acknowledged without being
	// stored; kinds that are always ingested are stored unless known.
	if err := a.store.RaiseCoverage(context.Background(), map[string]int64{"b": 10}); err != nil {
		t.Fatal(err)
	}
	if _, err := ingest(t, a.rep, "b", ev("b", 7, kindNote, "deleted note"), ev("b", 8, kindRule, "old rule"), ev("b", 9, kindRule, "one")); err != nil {
		t.Fatal(err)
	}
	if a.store.has("b", 7) || !a.store.has("b", 8) {
		t.Fatal("below the coverage: note stored or rule dropped")
	}
	// ...and they are verified like any other event.
	if _, err := ingest(t, a.rep, "b", ev("b", 6, kindRule, "bad rule")); !errors.Is(err, replication.ErrRejected) {
		t.Fatalf("unverified rule below coverage: %v", err)
	}
}

func TestPushStopsAtRejection(t *testing.T) {
	nodes := cluster(t, []string{"a", "b"}, map[string][]string{"a": {"b"}})
	a := nodes["a"]
	a.store.local(kindNote, "fine")
	a.store.local(kindNote, "bad news")
	a.store.local(kindNote, "after")
	n, err := a.rep.Push(context.Background(), "b")
	if err == nil || n != 0 {
		t.Fatalf("push: %d, %v", n, err)
	}
	if c, _ := a.store.Cursor(context.Background(), "b"); c != 1 {
		t.Fatalf("cursor %d, want 1", c)
	}
	if nodes["b"].store.has("a", 3) {
		t.Fatal("event after the rejected one stored")
	}
}

// liar acknowledges more than it was sent.
func TestCursorNotAdvancedBeyondPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(replication.Ack{V: 1, Accepted: 1000})
	}))
	defer srv.Close()
	st := newMemStore("a")
	r, err := replication.New(replication.Config{
		Self: "a", Peers: []replication.Peer{{Name: "b", URL: srv.URL}}, Store: st,
		Verify:             func(context.Context, replication.Event) error { return nil },
		CheckpointKind:     kindCheckpoint,
		CheckpointCoverage: func(replication.Event) (map[string]int64, error) { return nil, nil },
		Client:             func(string) *http.Client { return srv.Client() },
	})
	if err != nil {
		t.Fatal(err)
	}
	st.local(kindNote, "one")
	if _, err := r.Push(context.Background(), "b"); err == nil {
		t.Fatal("acknowledgment beyond the page accepted")
	}
	if c, _ := st.Cursor(context.Background(), "b"); c != 0 {
		t.Fatalf("cursor %d", c)
	}
}

func TestPullAfterCompactionStartsWithCheckpoint(t *testing.T) {
	nodes := cluster(t, []string{"a", "b", "c"}, map[string][]string{"a": {"b"}, "b": {"a"}, "c": {"a"}})
	a, b, c := nodes["a"], nodes["b"], nodes["c"]
	ctx := context.Background()
	for i := range 5 {
		a.store.local(kindNote, "note "+strconv.Itoa(i))
	}
	cov, _ := a.store.Coverage(ctx, "a")
	a.store.local(kindCheckpoint, checkpointBody(map[string]int64{"a": cov}))
	a.store.local(kindNote, "after the checkpoint")

	// Nothing is acknowledged by b yet: no frontier.
	if cp, err := a.rep.Frontier(ctx); err != nil || cp != nil {
		t.Fatalf("frontier without acknowledgment: %v, %v", cp, err)
	}
	if _, err := a.rep.Push(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	cp, err := a.rep.Frontier(ctx)
	if err != nil || cp == nil || cp.Seq != 6 {
		t.Fatalf("frontier: %v, %v", cp, err)
	}
	a.store.compact()
	if a.store.has("a", 1) || !a.store.has("a", 6) {
		t.Fatal("compaction")
	}

	// c is new: its pull starts with a's checkpoint and gets the rest.
	res, err := c.rep.Pull(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Checkpoint {
		t.Fatal("pull did not start with the checkpoint")
	}
	if !c.store.has("a", 6) || !c.store.has("a", 7) || c.store.has("a", 1) {
		t.Fatal("pulled journal")
	}
	if got, _ := c.store.Coverage(ctx, "a"); got != 7 {
		t.Fatalf("coverage after pull %d, want 7", got)
	}
	// A peer cannot push back what compaction deleted.
	if _, err := ingest(t, a.rep, "b", ev("a", 2, kindNote, "note 1")); err != nil {
		t.Fatal(err)
	}
	if a.store.has("a", 2) {
		t.Fatal("deleted event pushed back")
	}
	_ = b
}

func TestHandlerRefusesUnknownPeers(t *testing.T) {
	nodes := cluster(t, []string{"a", "b"}, nil)
	srv := nodes["a"].srv
	for _, peer := range []string{"", "x"} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+replication.PathEvents+"?after=0", nil)
		if peer != "" {
			req.Header.Set("X-Test-Peer", peer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("peer %q: %d", peer, resp.StatusCode)
		}
	}
	// A page on behalf of another instance is refused.
	body := `{"v":1,"instance":"a","events":[]}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+replication.PathIngest, strings.NewReader(body))
	req.Header.Set("X-Test-Peer", "b")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("page for another instance: %d", resp.StatusCode)
	}
}

// The package must not depend on ergosum, so that it can be moved out.
func TestNoErgosumImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.Contains(p, ".") { // not the standard library
				bad = append(bad, fmt.Sprintf("%s imports %s", f, p))
			}
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatal(strings.Join(bad, "\n"))
	}
}
