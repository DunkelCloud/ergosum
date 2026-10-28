package replication_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ergosum/internal/replication"
)

// TestPagesAreCutToSize: pages stay within the receiver's limit, so a few
// large events do not stall the outbox; a single event over the limit is
// refused with a clear error and only that event waits.
func TestPagesAreCutToSize(t *testing.T) {
	small := func(c *replication.Config) { c.MaxBody = 64 << 10 }
	nodes := cluster(t, []string{"a", "b", "c"}, map[string][]string{"a": {"b"}, "c": {"a"}}, small)
	a, b, c := nodes["a"], nodes["b"], nodes["c"]
	ctx := context.Background()
	for i := range 10 {
		a.store.local(kindNote, strconv.Itoa(i)+strings.Repeat("x", 10<<10))
	}
	for cov := int64(0); cov < 10; cov, _ = b.store.Coverage(ctx, "a") {
		n, err := a.rep.Push(ctx, "b")
		if err != nil || n == 0 || n == 10 {
			t.Fatalf("push: %d events, %v", n, err)
		}
	}
	// c pulls in pages of the same size.
	res, err := c.rep.Pull(ctx, "a")
	if err != nil || res.Events != 10 || res.Pages < 2 {
		t.Fatalf("pull: %+v, %v", res, err)
	}

	a.store.local(kindNote, strings.Repeat("y", 100<<10))
	_, err = a.rep.Push(ctx, "b")
	if err == nil || !strings.Contains(err.Error(), "413") {
		t.Fatalf("push of an event over the limit: %v", err)
	}
	if cur, _ := a.store.Cursor(ctx, "b"); cur != 10 {
		t.Fatalf("cursor %d, want 10", cur)
	}
}

// TestPushWithoutProgressFails: a peer that answers 200 without accepting
// the page gets the backoff of a failure, not the same page again at once.
func TestPushWithoutProgressFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(replication.Ack{V: 1, Accepted: 0})
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
		t.Fatal("an acknowledgment without progress counted as success")
	}
}

// TestTemporaryVerifyFailure: an error of Verify that is no verdict on the
// event stops the page without a rejection or an alarm; the sender
// retries.
func TestTemporaryVerifyFailure(t *testing.T) {
	var alarms atomic.Int64
	onReject := func(c *replication.Config) {
		c.OnReject = func(string, replication.Event, error) { alarms.Add(1) }
	}
	nodes := cluster(t, []string{"a", "b"}, map[string][]string{"a": {"b"}}, onReject)
	a := nodes["a"]
	acc, err := ingest(t, a.rep, "b", ev("b", 1, kindNote, "one"), ev("b", 2, kindNote, "flaky two"))
	if err == nil || errors.Is(err, replication.ErrRejected) || acc != 1 {
		t.Fatalf("temporary failure: accepted %d, %v", acc, err)
	}
	// Over HTTP the sender sees a temporary failure and keeps the event.
	a.store.local(kindNote, "flaky from a")
	if _, err := a.rep.Push(context.Background(), "b"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("push into a temporary failure: %v", err)
	}
	if cur, _ := a.store.Cursor(context.Background(), "b"); cur != 0 {
		t.Fatalf("cursor moved over an event that was not stored: %d", cur)
	}
	if n := alarms.Load(); n != 0 {
		t.Fatalf("%d alarms for temporary failures", n)
	}
}

// TestCoverageClaims: the coverage in the checkpoint a page starts with
// counts only on a pull, which an operator starts; a pushed one could make
// the receiver skip a third instance's events or raise its own sequence
// counter. Numbers above MaxSeq are refused either way.
func TestCoverageClaims(t *testing.T) {
	nodes := cluster(t, []string{"a", "b", "c"}, map[string][]string{"a": {"b"}, "c": {"b"}})
	a, b := nodes["a"], nodes["b"]
	ctx := context.Background()
	claim := b.store.local(kindCheckpoint, checkpointBody(map[string]int64{"a": 100, "b": 1, "c": 50}))
	b.store.compacted, b.store.frontCP = 1, &replication.Stored{Pos: 1, Event: claim}

	p := replication.Page{V: replication.Version, Instance: "b", Start: &replication.Stored{Pos: 1, Event: claim}, Last: 1}
	if _, err := a.rep.Ingest(ctx, "b", p); err != nil {
		t.Fatal(err)
	}
	if !a.store.has("b", 1) {
		t.Fatal("pushed checkpoint not stored")
	}
	if a.store.cov["a"] != 0 || a.store.cov["c"] != 0 {
		t.Fatalf("a pushed checkpoint raised the coverage: %v", a.store.cov)
	}
	if _, err := a.rep.Pull(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	if a.store.cov["a"] != 100 || a.store.cov["c"] != 50 {
		t.Fatalf("a pulled checkpoint did not raise the coverage: %v", a.store.cov)
	}

	big := b.store.local(kindCheckpoint, checkpointBody(map[string]int64{"c": replication.MaxSeq + 1}))
	b.store.frontCP, b.store.compacted = &replication.Stored{Pos: 2, Event: big}, 2
	if _, err := nodes["c"].rep.Pull(ctx, "b"); !errors.Is(err, replication.ErrRejected) {
		t.Fatalf("coverage above MaxSeq: %v", err)
	}
	if _, err := ingest(t, a.rep, "b", ev("b", replication.MaxSeq+1, kindNote, "far")); !errors.Is(err, replication.ErrRejected) {
		t.Fatalf("sequence number above MaxSeq: %v", err)
	}
}
