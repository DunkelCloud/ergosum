package journal_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ergosum/internal/journal"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/replication"
)

// pair opens two instances that know each other's keys.
func pair(t *testing.T, admins *jt.Admins) (a, b *journal.Store) {
	t.Helper()
	ka, kb := newKey(t), newKey(t)
	a = openInstance(t, admins, 1, "instance-a", ka)
	b = openInstance(t, admins, 1, "instance-b", kb)
	both := map[string]*ecdsa.PublicKey{"instance-a": &ka.PublicKey, "instance-b": &kb.PublicKey}
	a.SetInstanceKeys(both)
	b.SetInstanceKeys(both)
	return a, b
}

// copyEvents ingests every event of from above position after into to, as
// the replicator would.
func copyEvents(t *testing.T, from, to *journal.Store, after int64) int64 {
	t.Helper()
	ctx := context.Background()
	_, events, last, err := from.Read(ctx, after, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if err := to.Verify(ctx, e.Event); err != nil {
			t.Fatalf("%s/%d: %v", e.Origin, e.Seq, err)
		}
		if err := to.Append(ctx, e.Event); err != nil {
			t.Fatal(err)
		}
	}
	return last
}

// TestVerifyChecksPosition: every event carries its origin's signature
// over (origin, seq, kind, hash), so a peer cannot put a valid event under
// another origin or sequence number, where it would make the genuine event
// conflict.
func TestVerifyChecksPosition(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice")
	a, b := pair(t, admins)
	if _, err := a.AppendBinding(ctx, admins.Sign(t, jt.Set(td, "host1.example.com", 1, fingerprint(t), tailnet), "alice")); err != nil {
		t.Fatal(err)
	}
	_, events, _, err := a.Read(ctx, 0, 10)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	genuine := events[0].Event
	for name, mutate := range map[string]func(*replication.Event){
		"other origin":   func(e *replication.Event) { e.Origin = "instance-b" },
		"other seq":      func(e *replication.Event) { e.Seq = 7 },
		"no signature":   func(e *replication.Event) { e.Sig = nil },
		"unknown origin": func(e *replication.Event) { e.Origin = "instance-c" },
		"cut signature":  func(e *replication.Event) { e.Sig = append([]byte{}, e.Sig[:len(e.Sig)-1]...) },
	} {
		e := genuine
		mutate(&e)
		err := b.Verify(ctx, e)
		if !errors.Is(err, replication.ErrInvalid) || !errors.Is(err, journal.ErrUnverified) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := b.Verify(ctx, genuine); err != nil {
		t.Fatal(err)
	}
	// A failure to check is not a verdict on the event: the replicator
	// retries instead of rejecting.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := b.Verify(canceled, genuine); err == nil || errors.Is(err, replication.ErrInvalid) {
		t.Fatalf("verify with a canceled context: %v", err)
	}
}

// TestCompactWithTemporaryDataInMemory: SQLite keeps temporary data in
// memory, so that compaction needs no writable temporary directory, which a
// read-only container without /tmp does not have. The delete trigger makes
// SQLite keep a statement journal of the pages that the compaction's DELETE
// changes; deleting 100 events of about 1 KiB takes it past the 64 KiB at
// which it would spill to a temporary file (in such a container, it failed
// with "disk I/O error (6410)").
func TestCompactWithTemporaryDataInMemory(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, jt.NewAdmins(t, "alice"), 1)
	if v, err := journal.TempStoreForTest(s); err != nil || v != 2 {
		t.Fatalf("temp_store %d, %v; want 2 (MEMORY)", v, err)
	}
	body := []byte(`{"pad":"` + strings.Repeat("x", 1100) + `"}`)
	const n = 100
	for range n {
		if _, err := s.AppendObservation(ctx, "observation.issued", "host1.example.com", "h", body); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.WriteCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	cp, _ := s.LatestAt(ctx, "instance-a", journal.KindCheckpoint, math.MaxInt64)
	cov, _ := s.Coverages(ctx)
	if err := s.SetFrontier(ctx, *cp, cov); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if got, err := s.Compact(ctx, journal.CompactOptions{Retention: journal.Retention{Observations: time.Nanosecond}}); err != nil || got != n {
		t.Fatalf("compacted %d of %d: %v", got, n, err)
	}
}

// TestReadPagesAfterCompaction: paging from below the compaction frontier
// delivers every event that survived compaction, not only the first page.
func TestReadPagesAfterCompaction(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice")
	s := newStore(t, admins, 1)
	for i := uint64(1); i <= 6; i++ { // binding history, kept
		if _, err := s.AppendBinding(ctx, admins.Sign(t, jt.Set(td, "host1.example.com", i, fingerprint(t), tailnet), "alice")); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		if _, err := s.AppendObservation(ctx, "observation.issued", "host1.example.com", "h", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.WriteCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	cp, _ := s.LatestAt(ctx, "instance-a", journal.KindCheckpoint, math.MaxInt64)
	cov, _ := s.Coverages(ctx)
	if err := s.SetFrontier(ctx, *cp, cov); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if n, err := s.Compact(ctx, journal.CompactOptions{Retention: journal.Retention{Observations: time.Nanosecond}}); err != nil || n != 3 {
		t.Fatalf("compacted %d, %v", n, err)
	}
	_, all, _, _ := s.Read(ctx, 0, 1000)
	var got []int64
	var after int64
	for {
		start, events, last, err := s.Read(ctx, after, 2)
		if err != nil {
			t.Fatal(err)
		}
		if start == nil && after < 9 {
			t.Fatalf("page after %d below the compaction without its checkpoint", after)
		}
		for _, e := range events {
			got = append(got, e.Pos)
		}
		if len(events) < 2 {
			break
		}
		after = last
	}
	if len(got) != len(all) {
		t.Fatalf("paging delivered positions %v of %d stored events", got, len(all))
	}
}

type slowWriter struct{ d time.Duration }

func (w slowWriter) Write(p []byte) (int, error) { time.Sleep(w.d); return len(p), nil }

// TestExportReleasesTheDatabase: a slow reader of an export does not hold
// up issuance, which needs the same database.
func TestExportReleasesTheDatabase(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice")
	s := newStore(t, admins, 1)
	for range 20 {
		if _, err := s.AppendObservation(ctx, "observation.issued", "host1.example.com", "h", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = s.Export(ctx, slowWriter{50 * time.Millisecond}, 0)
	}()
	time.Sleep(100 * time.Millisecond)
	c, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if _, err := s.Binding(c, "host1.example.com"); err != nil {
		t.Fatalf("lookup during an export: %v", err)
	}
	<-done
}

// TestPeerCheckpointsAreNoChange: a peer's checkpoint does not make the
// journal due for a checkpoint of its own; anything else does.
func TestPeerCheckpointsAreNoChange(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice")
	a, b := pair(t, admins)
	if _, err := a.AppendBinding(ctx, admins.Sign(t, jt.Set(td, "host1.example.com", 1, fingerprint(t), tailnet), "alice")); err != nil {
		t.Fatal(err)
	}
	pos := copyEvents(t, a, b, 0)
	if _, err := b.WriteCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.WriteCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	pos = copyEvents(t, a, b, pos)
	if changed, err := b.ChangedSinceCheckpoint(ctx); err != nil || changed {
		t.Fatalf("after a peer's checkpoint: changed %v, %v", changed, err)
	}
	if _, err := a.AppendBinding(ctx, admins.Sign(t, jt.Revoke(td, "host1.example.com", 2), "alice")); err != nil {
		t.Fatal(err)
	}
	copyEvents(t, a, b, pos)
	if changed, err := b.ChangedSinceCheckpoint(ctx); err != nil || !changed {
		t.Fatalf("after a peer's binding event: changed %v, %v", changed, err)
	}
}

// TestRemovedOrigin: an instance taken out of the configuration leaves its
// coverage in the checkpoints of instances that saw its events. Those
// checkpoints still verify, and new checkpoints no longer mention it.
func TestRemovedOrigin(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice")
	ka, kb, kc := newKey(t), newKey(t), newKey(t)
	a := openInstance(t, admins, 1, "instance-a", ka)
	b := openInstance(t, admins, 1, "instance-b", kb)
	c := openInstance(t, admins, 1, "instance-c", kc)
	all := map[string]*ecdsa.PublicKey{"instance-a": &ka.PublicKey, "instance-b": &kb.PublicKey, "instance-c": &kc.PublicKey}
	for _, s := range []*journal.Store{a, b, c} {
		s.SetInstanceKeys(all)
	}
	if _, err := c.AppendBinding(ctx, admins.Sign(t, jt.Set(td, "host1.example.com", 1, fingerprint(t), tailnet), "alice")); err != nil {
		t.Fatal(err)
	}
	copyEvents(t, c, a, 0)
	if _, err := a.WriteCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	_, events, _, err := a.Read(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	cp := events[len(events)-1].Event
	if cov, _ := a.CheckpointCoverage(cp); cov["instance-c"] == 0 {
		t.Fatalf("checkpoint without C's coverage: %v", cov)
	}
	// C leaves the configuration of A and B.
	ab := map[string]*ecdsa.PublicKey{"instance-a": &ka.PublicKey, "instance-b": &kb.PublicKey}
	a.SetInstanceKeys(ab)
	b.SetInstanceKeys(ab)
	if err := b.Verify(ctx, cp); err != nil {
		t.Fatalf("a checkpoint covering a removed instance: %v", err)
	}
	if cov, _ := b.CheckpointCoverage(cp); cov["instance-c"] != 0 {
		t.Fatalf("coverage of a removed instance taken over: %v", cov)
	}
	if _, err := a.WriteCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	_, events, _, _ = a.Read(ctx, 0, 100)
	if cov, _ := a.CheckpointCoverage(events[len(events)-1].Event); cov["instance-c"] != 0 {
		t.Fatalf("new checkpoint covers a removed instance: %v", cov)
	}
}

// TestRelayedBodyStoredCanonically: the position signature covers the hash
// of the canonical text, not the body, so a relay may respell the body. A
// binding event is stored as this instance would write it.
func TestRelayedBodyStoredCanonically(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice")
	a, b := pair(t, admins)
	if _, err := a.AppendBinding(ctx, admins.Sign(t, jt.Set(td, "host1.example.com", 1, fingerprint(t), tailnet), "alice")); err != nil {
		t.Fatal(err)
	}
	_, events, _, err := a.Read(ctx, 0, 10)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	e := events[0].Event
	canonical := string(e.Body)
	e.Body = []byte(strings.Replace(canonical, `"identity":`, `"IDENTITY":"host1.example.com","identity":`, 1))
	if err := b.Verify(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := b.Append(ctx, e); err != nil {
		t.Fatal(err)
	}
	bodies, err := b.EventBodies(ctx, journal.KindBindingSet)
	if err != nil || len(bodies) != 1 {
		t.Fatal(bodies, err)
	}
	if string(bodies[0]) != canonical {
		t.Fatalf("stored body %s, want %s", bodies[0], canonical)
	}
}

// TestProjectionVersion: the version changes with every change of the
// projection, written here or ingested, and not with observations.
func TestProjectionVersion(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice")
	a, b := pair(t, admins)
	if _, err := a.AppendBinding(ctx, admins.Sign(t, jt.Set(td, "host1.example.com", 1, fingerprint(t), tailnet), "alice")); err != nil {
		t.Fatal(err)
	}
	if a.ProjectionVersion() == 0 {
		t.Fatal("a binding written here left the version")
	}
	before := b.ProjectionVersion()
	copyEvents(t, a, b, 0)
	if b.ProjectionVersion() == before {
		t.Fatal("an ingested binding left the version")
	}
	before = a.ProjectionVersion()
	if _, err := a.AppendObservation(ctx, journal.KindObservation+".issued", "host1.example.com", strings.Repeat("0", 64), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if a.ProjectionVersion() != before {
		t.Fatal("an observation changed the version")
	}
}

// TestHeldBindingsNotVerifiedAgain: a checkpoint repeats every binding; one
// that an instance holds with the same body verified when it was stored,
// and is not checked against the registry again. An instance that does
// not hold it still verifies it: there a binding approved only by an
// administrator who has since left the registry fails.
func TestHeldBindingsNotVerifiedAgain(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice", "bob")
	ka, kb := newKey(t), newKey(t)
	all := map[string]*ecdsa.PublicKey{"instance-a": &ka.PublicKey, "instance-b": &kb.PublicKey}
	open := func(path, name string, cfg journal.RegistryConfig, key *ecdsa.PrivateKey) *journal.Store {
		t.Helper()
		reg, err := journal.NewRegistry(cfg)
		if err != nil {
			t.Fatal(err)
		}
		s, err := journal.Open(path, name, td, reg)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetSigner(ctx, key); err != nil {
			t.Fatal(err)
		}
		s.SetInstanceKeys(all)
		return s
	}
	a := open(filepath.Join(t.TempDir(), "a.db"), "instance-a", admins.Registry(1), ka)
	defer a.Close()
	bPath := filepath.Join(t.TempDir(), "b.db")
	b := open(bPath, "instance-b", admins.Registry(1), kb)
	if _, err := a.AppendBinding(ctx, admins.Sign(t, jt.Set(td, "host1.example.com", 1, fingerprint(t), tailnet), "bob")); err != nil {
		t.Fatal(err)
	}
	after := copyEvents(t, a, b, 0)
	b.Close()

	// bob leaves the registry; b still holds the binding he approved.
	withoutBob := admins.Registry(1)
	delete(withoutBob.Admins, "bob")
	for kind, ap := range withoutBob.Approvals {
		ap.Keys = []string{"alice"}
		withoutBob.Approvals[kind] = ap
	}
	b = open(bPath, "instance-b", withoutBob, kb)
	defer b.Close()
	if _, err := a.WriteCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	_, events, _, err := a.Read(ctx, after, 10)
	if err != nil || len(events) != 1 || events[0].Kind != journal.KindCheckpoint {
		t.Fatalf("%v %v", events, err)
	}
	if err := b.Verify(ctx, events[0].Event); err != nil {
		t.Fatalf("checkpoint with a held binding: %v", err)
	}
	c := open(filepath.Join(t.TempDir(), "c.db"), "instance-b", withoutBob, kb)
	defer c.Close()
	if err := c.Verify(ctx, events[0].Event); !errors.Is(err, journal.ErrUnverified) {
		t.Fatalf("instance without the binding: %v", err)
	}
}

// TestLatestAt: the frontier reads the newest own checkpoint at or below
// the acknowledged position, and only that one.
func TestLatestAt(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice")
	s := newStore(t, admins, 1)
	var pos []int64
	for range 3 {
		if _, err := s.AppendBinding(ctx, admins.Sign(t, jt.Set(td, "host1.example.com", uint64(len(pos)+1), fingerprint(t), tailnet), "alice")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.WriteCheckpoint(ctx); err != nil {
			t.Fatal(err)
		}
		_, events, _, _ := s.Read(ctx, 0, 100)
		pos = append(pos, events[len(events)-1].Pos)
	}
	for _, c := range []struct{ at, want int64 }{{pos[0] - 1, 0}, {pos[0], pos[0]}, {pos[2] - 1, pos[1]}, {math.MaxInt64, pos[2]}} {
		cp, err := s.LatestAt(ctx, "instance-a", journal.KindCheckpoint, c.at)
		if err != nil {
			t.Fatal(err)
		}
		var got int64
		if cp != nil {
			got = cp.Pos
		}
		if got != c.want {
			t.Errorf("at %d: %d, want %d", c.at, got, c.want)
		}
	}
}
