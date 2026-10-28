package journal

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// Checkpoint is the payload of a checkpoint event (ADR 0003, Checkpoints
// and compaction): the projection with every winning binding event
// verbatim, the coverage per origin and the state hash. The instance
// signature over it says who wrote it and when; it grants nothing.
type Checkpoint struct {
	V           int               `json:"v"`
	Type        string            `json:"type"`
	TrustDomain string            `json:"trust_domain"`
	Instance    string            `json:"instance"`
	Kid         string            `json:"kid"`
	CreatedAt   time.Time         `json:"created_at"`
	Coverage    map[string]int64  `json:"coverage"`
	Bindings    []json.RawMessage `json:"bindings"`
	StateHash   string            `json:"state_hash"`
}

const checkpointType = "checkpoint"

// decodeCheckpoint reads the payload of a stored checkpoint event without
// verifying it; ingest has verified it before it was stored.
func decodeCheckpoint(body []byte) (*Checkpoint, error) {
	var cp Checkpoint
	if err := decodeEnvelopePayload(body, &cp); err != nil {
		return nil, err
	}
	return &cp, nil
}

// stateLine is one line of the state hash: "<identity> <epoch> <hash>".
func stateLine(identity string, epoch uint64, hash string) string {
	return identity + " " + strconv.FormatUint(epoch, 10) + " " + hash + "\n"
}

func stateHash(lines []string) string {
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "")))
	return hex.EncodeToString(sum[:])
}

// verifyCheckpoint checks a checkpoint payload whose envelope verified with
// the instance key of origin: every contained binding event is verified
// against the local registry and trust domain like a write; one failure
// rejects the whole checkpoint.
func (s *Store) verifyCheckpoint(origin string, payload []byte) (*Checkpoint, error) {
	var cp Checkpoint
	if err := strictDecode(payload, &cp); err != nil {
		return nil, unverified("checkpoint: %v", err)
	}
	switch {
	case cp.V != 1 || cp.Type != checkpointType:
		return nil, unverified("checkpoint version %d, type %q", cp.V, cp.Type)
	case cp.Instance != origin:
		return nil, unverified("checkpoint of %q stored under origin %q", cp.Instance, origin)
	case cp.TrustDomain != s.trustDomain:
		return nil, unverified("checkpoint for trust domain %q", cp.TrustDomain)
	case cp.CreatedAt.IsZero():
		return nil, unverified("checkpoint without time")
	}
	for o, n := range cp.Coverage {
		if n < 0 || (o != s.origin && s.instanceKey(o) == nil) {
			return nil, unverified("checkpoint coverage of unknown origin %q", o)
		}
	}
	seen := map[string]bool{}
	lines := make([]string, 0, len(cp.Bindings))
	for i, raw := range cp.Bindings {
		be, err := s.verifyBinding(raw)
		if err != nil {
			return nil, fmt.Errorf("checkpoint binding %d: %w", i+1, err)
		}
		if seen[be.Identity] {
			return nil, unverified("checkpoint holds %s twice", be.Identity)
		}
		seen[be.Identity] = true
		h, _ := be.Hash()
		lines = append(lines, stateLine(be.Identity, be.Epoch, h))
	}
	if stateHash(lines) != cp.StateHash {
		return nil, unverified("checkpoint state hash does not match its bindings")
	}
	return &cp, nil
}

// applyCheckpoint applies the bindings of a checkpoint under the ordering
// rule: the projection becomes the winner of the union, so a checkpoint
// that misses an event never undoes it.
func applyCheckpoint(ctx context.Context, q querier, cp *Checkpoint, origin string, seq int64) error {
	for _, raw := range cp.Bindings {
		var be BindingEvent
		if err := json.Unmarshal(raw, &be); err != nil {
			return err
		}
		h, err := be.Hash()
		if err != nil {
			return err
		}
		b := &Binding{Identity: be.Identity, Kind: be.Kind, Epoch: be.Epoch, Key: be.Key, Checks: be.SortedChecks(), Hash: h, Origin: origin, Seq: seq}
		if err := applyBinding(ctx, q, b, raw); err != nil {
			return err
		}
	}
	return nil
}

// StateHash returns the hex SHA-256 over one line "<identity> <epoch>
// <event hash>" per projected identity, sorted. Instances that hold the
// same binding events have the same state hash.
func (s *Store) StateHash(ctx context.Context) (string, error) {
	return projectionHash(ctx, s.db)
}

func projectionHash(ctx context.Context, q querier) (string, error) {
	rows, err := q.QueryContext(ctx, `SELECT identity, epoch, hash FROM bindings`)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()
	var lines []string
	for rows.Next() {
		var id, h string
		var epoch uint64
		if err := rows.Scan(&id, &epoch, &h); err != nil {
			return "", err
		}
		lines = append(lines, stateLine(id, epoch, h))
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return stateHash(lines), nil
}

// WriteCheckpoint records a checkpoint of the current projection and
// coverage, signed with the instance key.
func (s *Store) WriteCheckpoint(ctx context.Context, key *ecdsa.PrivateKey) (Receipt, error) {
	if key == nil {
		return Receipt{}, errors.New("journal: a checkpoint needs the unsealed instance key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	cov, err := originMap(ctx, tx, `SELECT origin, seq FROM coverage WHERE seq > 0`)
	if err != nil {
		return Receipt{}, err
	}
	cp := Checkpoint{
		V: 1, Type: checkpointType, TrustDomain: s.trustDomain, Instance: s.origin,
		Kid: keys.Thumbprint(&key.PublicKey), CreatedAt: s.now().UTC(), Coverage: cov,
		Bindings: []json.RawMessage{},
	}
	rows, err := tx.QueryContext(ctx, `SELECT body FROM bindings ORDER BY identity`)
	if err != nil {
		return Receipt{}, err
	}
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			_ = rows.Close()
			return Receipt{}, err
		}
		cp.Bindings = append(cp.Bindings, json.RawMessage(body))
	}
	_ = rows.Close()
	if cp.StateHash, err = projectionHash(ctx, tx); err != nil {
		return Receipt{}, err
	}
	env, err := protocol.Seal(key, protocol.ContextCheckpoint, cp)
	if err != nil {
		return Receipt{}, err
	}
	body, err := json.Marshal(env)
	if err != nil {
		return Receipt{}, err
	}
	payload, _ := base64.RawURLEncoding.DecodeString(env.Payload)
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	seq, err := s.insertOwn(ctx, tx, KindCheckpoint, "", 0, hash, body)
	if err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return Receipt{Origin: s.origin, Seq: seq, Hash: hash}, nil
}

// LastCheckpoint returns when the latest own checkpoint was recorded, or
// the zero time.
func (s *Store) LastCheckpoint(ctx context.Context) (time.Time, error) {
	var at sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT MAX(recorded_at) FROM events WHERE origin = ? AND kind = ?`, s.origin, KindCheckpoint).Scan(&at)
	if err != nil || !at.Valid {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, at.String)
}

// ChangedSinceCheckpoint reports whether events were stored after the
// latest own checkpoint, or there is none and the journal is not empty.
func (s *Store) ChangedSinceCheckpoint(ctx context.Context) (bool, error) {
	var changed bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM events WHERE pos >
		COALESCE((SELECT MAX(pos) FROM events WHERE origin = ? AND kind = ?), 0))`, s.origin, KindCheckpoint).Scan(&changed)
	return changed, err
}

// Retention is how long events stay after their checkpoint covers them;
// zero keeps them.
type Retention struct {
	Observations time.Duration // all observations but key_duplicate
	KeyDuplicate time.Duration
	Bindings     time.Duration
}

// CompactOptions are the conditions of a compaction besides the frontier.
type CompactOptions struct {
	// Peers are the peers that receive pushes; every one of them must have
	// acknowledged an event before it is deleted.
	Peers     []string
	Retention Retention
	// Archived: an archive is configured, so only exported events may go.
	Archived bool
}

// compactable selects the events that may be deleted: at or below the
// frontier of their origin, acknowledged by every peer, exported if an
// archive is configured, and past the retention of their kind. A
// checkpoint goes once a newer checkpoint of its origin is at or below the
// frontier. The parameters are: the position limit, then cutoff time twice
// for observations, key_duplicate and binding events (empty: keep).
const compactable = `pos <= ?1
	AND seq <= COALESCE((SELECT c.seq FROM compaction c WHERE c.origin = events.origin), 0)
	AND (
		(kind = 'checkpoint' AND EXISTS (SELECT 1 FROM events n WHERE n.origin = events.origin AND n.kind = 'checkpoint'
			AND n.seq > events.seq AND n.seq <= COALESCE((SELECT c.seq FROM compaction c WHERE c.origin = events.origin), 0)))
		OR (kind LIKE 'observation.%' AND kind <> 'observation.key_duplicate' AND ?2 <> '' AND recorded_at < ?2)
		OR (kind = 'observation.key_duplicate' AND ?3 <> '' AND recorded_at < ?3)
		OR (kind LIKE 'binding.%' AND ?4 <> '' AND recorded_at < ?4)
	)`

// Compact deletes what the frontier and the options allow and returns the
// number of deleted events. The delete trigger refuses any event above the
// frontier, whatever this query selects.
func (s *Store) Compact(ctx context.Context, o CompactOptions) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	limit := int64(math.MaxInt64)
	for _, p := range o.Peers {
		var c int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT pos FROM peer_cursor WHERE peer = ?), 0)`, p).Scan(&c); err != nil {
			return 0, err
		}
		limit = min(limit, c)
	}
	if o.Archived {
		exported, err := metaInt(ctx, tx, "exported_pos")
		if err != nil {
			return 0, err
		}
		limit = min(limit, exported)
	}
	now := s.now().UTC()
	cutoff := func(d time.Duration) string {
		if d <= 0 {
			return ""
		}
		return now.Add(-d).Format(time.RFC3339Nano)
	}
	args := []any{limit, cutoff(o.Retention.Observations), cutoff(o.Retention.KeyDuplicate), cutoff(o.Retention.Bindings)}
	var n, maxPos int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MAX(pos), 0) FROM events WHERE `+compactable, args...).Scan(&n, &maxPos); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	if err := raiseMetaInt(ctx, tx, "compacted_pos", maxPos); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE `+compactable, args...); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// ArchiveLine is one event in an export: JSON lines that need no trust in
// whoever stores them, because observations and checkpoints are signed by
// their instance and binding events by administrators.
type ArchiveLine struct {
	Origin string          `json:"origin"`
	Seq    int64           `json:"seq"`
	Kind   string          `json:"kind"`
	Hash   string          `json:"hash"`
	Body   json.RawMessage `json:"body"`
}

// Export writes every event above position after as JSON lines, in
// insertion order, and returns the last position written.
func (s *Store) Export(ctx context.Context, w io.Writer, after int64) (last int64, n int, err error) {
	rows, err := s.db.QueryContext(ctx, `SELECT pos, origin, seq, kind, hash, body FROM events WHERE pos > ? ORDER BY pos`, after)
	if err != nil {
		return after, 0, err
	}
	defer func() { _ = rows.Close() }()
	last = after
	for rows.Next() {
		var l ArchiveLine
		var body []byte
		if err := rows.Scan(&last, &l.Origin, &l.Seq, &l.Kind, &l.Hash, &body); err != nil {
			return last, n, err
		}
		l.Body = body
		data, err := json.Marshal(l)
		if err != nil {
			return last, n, err
		}
		if _, err := w.Write(append(data, '\n')); err != nil {
			return last, n, err
		}
		n++
	}
	return last, n, rows.Err()
}

// ExportArchive writes the events not yet archived to a new file in dir
// and records them as exported, so that compaction may delete them. It
// returns the file name, or "" if there was nothing new.
func (s *Store) ExportArchive(ctx context.Context, dir string) (path string, n int, err error) {
	after, err := metaInt(ctx, s.db, "exported_pos")
	if err != nil {
		return "", 0, err
	}
	var buf bytes.Buffer
	last, n, err := s.Export(ctx, &buf, after)
	if err != nil || n == 0 {
		return "", 0, err
	}
	path = filepath.Join(dir, fmt.Sprintf("%s-%012d-%012d.jsonl", s.origin, after+1, last))
	if err := keys.WriteFileAtomic(path, buf.Bytes(), 0o640); err != nil {
		return "", 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return path, n, raiseMetaInt(ctx, s.db, "exported_pos", last)
}

// State summarizes the journal for operators and monitoring.
type State struct {
	Instance       string           `json:"instance"`
	StateHash      string           `json:"state_hash"`
	Bindings       int              `json:"bindings"`
	Events         int              `json:"events"`
	NextSeq        int64            `json:"next_seq"`
	Coverage       map[string]int64 `json:"coverage"`
	Frontier       map[string]int64 `json:"frontier"`
	LastCheckpoint *time.Time       `json:"last_checkpoint,omitempty"`
}

// State returns the current state of the journal.
func (s *Store) State(ctx context.Context) (State, error) {
	st := State{Instance: s.origin}
	var err error
	if st.StateHash, err = s.StateHash(ctx); err != nil {
		return st, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bindings`).Scan(&st.Bindings); err != nil {
		return st, err
	}
	if st.Events, err = s.Count(ctx, ""); err != nil {
		return st, err
	}
	if st.NextSeq, err = metaInt(ctx, s.db, "next_seq"); err != nil {
		return st, err
	}
	if st.Coverage, err = s.Coverages(ctx); err != nil {
		return st, err
	}
	if st.Frontier, err = s.Frontier(ctx); err != nil {
		return st, err
	}
	if t, err := s.LastCheckpoint(ctx); err != nil {
		return st, err
	} else if !t.IsZero() {
		st.LastCheckpoint = &t
	}
	return st, nil
}
