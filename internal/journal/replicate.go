package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
	"github.com/DunkelCloud/ergosum/internal/replication"
)

// The journal is the replication store of an authority instance.
var _ replication.Store = (*Store)(nil)

// Observation kinds an instance records (ADR 0003, Observations).
var observationKinds = map[string]bool{
	KindObservation + ".issued":         true,
	KindObservation + ".key_duplicate":  true,
	KindObservation + ".wrong_location": true,
	KindObservation + ".replay":         true,
	KindObservation + ".misdirected":    true,
}

// AlwaysIngest reports the kinds that ingest stores even at or below the
// coverage of their origin: binding events, so that no checkpoint and no
// coverage claim can keep a valid binding event out.
func AlwaysIngest(kind string) bool {
	return kind == KindBindingSet || kind == KindBindingRevoked
}

func strictDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// ErrUnverified wraps every reason why ingest refuses an event. It wraps
// replication.ErrInvalid; other errors of Verify are temporary.
var ErrUnverified = fmt.Errorf("%w: event does not verify", replication.ErrInvalid)

func unverified(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnverified, fmt.Sprintf(format, a...))
}

// Verify checks an event from another instance before it is stored: its
// position (origin, seq, kind, hash) against the instance key of its
// origin, binding events against the registry and the trust domain exactly
// as the write API does, observations and checkpoints against the instance
// key of their origin, and every binding inside a checkpoint like a binding
// event. The hash must match the content.
func (s *Store) Verify(ctx context.Context, e replication.Event) error {
	key := s.instanceKey(e.Origin)
	if key == nil {
		return unverified("no instance key for origin %q", e.Origin)
	}
	if !keys.Verify(key, protocol.ContextEvent, e.SigningInput(), e.Sig) {
		return unverified("the position %s/%d is not signed by %s", e.Origin, e.Seq, e.Origin)
	}
	switch {
	case AlwaysIngest(e.Kind):
		be, err := s.verifyBinding(e.Body)
		if err != nil {
			return err
		}
		if be.Kind != e.Kind {
			return unverified("kind %s in a %s event", be.Kind, e.Kind)
		}
		if h, _ := be.Hash(); h != e.Hash {
			return unverified("hash does not match the canonical form")
		}
		// An instance records an event once; the same event under a second
		// sequence number of one origin is not genuine.
		var seq int64
		err = s.db.QueryRowContext(ctx, `SELECT seq FROM events WHERE origin = ? AND hash = ? AND kind LIKE 'binding.%' AND seq <> ?`, e.Origin, e.Hash, e.Seq).Scan(&seq)
		if err == nil {
			return fmt.Errorf("%w: %s recorded this binding event already as %d", replication.ErrEquivocation, e.Origin, seq)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return nil
	case observationKinds[e.Kind]:
		payload, err := s.verifyEnvelope(e, protocol.ContextObservation)
		if err != nil {
			return err
		}
		var h observationHeader
		if err := json.Unmarshal(payload, &h); err != nil {
			return unverified("observation: %v", err)
		}
		if h.Kind != e.Kind || h.Instance != e.Origin || !protocol.ValidDNSName(h.Identity) {
			return unverified("observation header (%s, %s, %q) does not match", h.Kind, h.Instance, h.Identity)
		}
		return nil
	case e.Kind == KindCheckpoint:
		payload, err := s.verifyEnvelope(e, protocol.ContextCheckpoint)
		if err != nil {
			return err
		}
		_, err = s.verifyCheckpoint(e.Origin, payload)
		return err
	default:
		return unverified("unknown kind %q", e.Kind)
	}
}

// observationHeader is the part of an observation payload that ingest
// needs; the authority defines the whole payload.
type observationHeader struct {
	Kind     string `json:"kind"`
	Instance string `json:"instance"`
	Kid      string `json:"kid"`
	Identity string `json:"identity"`
}

func (s *Store) verifyBinding(body []byte) (*BindingEvent, error) {
	var be BindingEvent
	if err := strictDecode(body, &be); err != nil {
		return nil, unverified("binding event: %v", err)
	}
	if err := be.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	if be.TrustDomain != s.trustDomain {
		return nil, fmt.Errorf("%w: %w: %q", ErrUnverified, ErrTrustDomain, be.TrustDomain)
	}
	if _, err := s.registry.Verify(&be); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	return &be, nil
}

// verifyEnvelope checks an instance-signed body and returns its payload.
func (s *Store) verifyEnvelope(e replication.Event, sigContext string) ([]byte, error) {
	var env protocol.Envelope
	if err := strictDecode(e.Body, &env); err != nil {
		return nil, unverified("envelope: %v", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, unverified("envelope payload: %v", err)
	}
	if sum := sha256.Sum256(payload); hex.EncodeToString(sum[:]) != e.Hash {
		return nil, unverified("hash does not match the payload")
	}
	key := s.instanceKey(e.Origin)
	if key == nil {
		return nil, unverified("no instance key for origin %q", e.Origin)
	}
	if !env.Verify(key, sigContext) {
		return nil, unverified("signature does not verify with the instance key of %s", e.Origin)
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(payload, &h); err != nil || h.Kid != keys.Thumbprint(key) {
		return nil, unverified("kid %q is not the instance key of %s", h.Kid, e.Origin)
	}
	return payload, nil
}

// CheckpointCoverage returns the coverage of a verified checkpoint event.
func (s *Store) CheckpointCoverage(e replication.Event) (map[string]int64, error) {
	cp, err := decodeCheckpoint(e.Body)
	if err != nil {
		return nil, err
	}
	s.knownOrigins(cp.Coverage)
	return cp.Coverage, nil
}

// knownOrigins drops the coverage of origins without a configured key: an
// instance taken out of the configuration altogether. Its coverage means
// nothing here, and refusing it would stop replication between all
// instances that once saw its events.
func (s *Store) knownOrigins(cov map[string]int64) {
	for o := range cov {
		if o != s.origin && s.instanceKey(o) == nil {
			delete(cov, o)
		}
	}
}

// Read implements replication.Store.
func (s *Store) Read(ctx context.Context, after int64, limit int) (start *replication.Stored, events []replication.Stored, last int64, err error) {
	compacted, err := metaInt(ctx, s.db, "compacted_pos")
	if err != nil {
		return nil, nil, 0, err
	}
	last = after
	if after < compacted {
		fp, err := metaInt(ctx, s.db, "frontier_pos")
		if err != nil {
			return nil, nil, 0, err
		}
		if start, err = s.eventAt(ctx, fp); err != nil {
			return nil, nil, 0, fmt.Errorf("journal: checkpoint of the compaction frontier: %w", err)
		}
	}
	events, err = s.storedEvents(ctx, `WHERE pos > ? ORDER BY pos LIMIT ?`, after, limit)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(events) > 0 {
		last = events[len(events)-1].Pos
	}
	// Only a page that holds everything above after reaches past the
	// deleted positions; a full one ends at its last event, so that the
	// events that survived compaction further up are not skipped.
	if len(events) < limit {
		last = max(last, compacted)
	}
	return start, events, last, nil
}

const storedColumns = `SELECT pos, origin, seq, kind, hash, body, sig FROM events `

func (s *Store) storedEvents(ctx context.Context, where string, args ...any) ([]replication.Stored, error) {
	rows, err := s.db.QueryContext(ctx, storedColumns+where, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []replication.Stored
	for rows.Next() {
		var e replication.Stored
		if err := rows.Scan(&e.Pos, &e.Origin, &e.Seq, &e.Kind, &e.Hash, &e.Body, &e.Sig); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) eventAt(ctx context.Context, pos int64) (*replication.Stored, error) {
	events, err := s.storedEvents(ctx, `WHERE pos = ?`, pos)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, sql.ErrNoRows
	}
	return &events[0], nil
}

// Lookup implements replication.Store.
func (s *Store) Lookup(ctx context.Context, origin string, seq int64) (hash string, found bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT hash FROM events WHERE origin = ? AND seq = ?`, origin, seq).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return hash, err == nil, err
}

// Contains implements replication.Store. A binding event also counts as
// contained while the projection holds it, after compaction removed it.
func (s *Store) Contains(ctx context.Context, kind, hash string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM events WHERE kind = ? AND hash = ?
		UNION ALL SELECT 1 FROM bindings WHERE kind = ? AND hash = ? LIMIT 1`, kind, hash, kind, hash).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Coverage implements replication.Store.
func (s *Store) Coverage(ctx context.Context, origin string) (int64, error) {
	var c int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE((SELECT seq FROM coverage WHERE origin = ?), 0)`, origin).Scan(&c)
	return c, err
}

// Coverages returns the coverage of every origin.
func (s *Store) Coverages(ctx context.Context) (map[string]int64, error) {
	return s.originMap(ctx, `SELECT origin, seq FROM coverage`)
}

// Frontier returns the compaction frontier of every origin.
func (s *Store) Frontier(ctx context.Context) (map[string]int64, error) {
	return s.originMap(ctx, `SELECT origin, seq FROM compaction`)
}

func (s *Store) originMap(ctx context.Context, query string) (map[string]int64, error) {
	return originMap(ctx, s.db, query)
}

func originMap(ctx context.Context, q querier, query string) (map[string]int64, error) {
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int64{}
	for rows.Next() {
		var o string
		var n int64
		if err := rows.Scan(&o, &n); err != nil {
			return nil, err
		}
		out[o] = n
	}
	return out, rows.Err()
}

// Append implements replication.Store: it stores a verified event from
// another instance and applies it. A binding event is applied under the
// ordering rule; a checkpoint applies every binding it contains, which is
// a union and never removes anything.
func (s *Store) Append(ctx context.Context, e replication.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	var identity string
	var epoch uint64
	switch {
	case AlwaysIngest(e.Kind):
		var be BindingEvent
		if err := json.Unmarshal(e.Body, &be); err != nil {
			return err
		}
		// Stored as this instance would write it: a relayed body may spell
		// fields in ways (duplicate keys in other case) that other readers
		// of an export would understand differently. The position signature
		// covers the hash of the canonical text, not the body.
		if e.Body, err = json.Marshal(&be); err != nil {
			return err
		}
		identity, epoch = be.Identity, be.Epoch
		b := &Binding{Identity: be.Identity, Kind: be.Kind, Epoch: be.Epoch, Key: be.Key, Checks: be.SortedChecks(), Hash: e.Hash, Origin: e.Origin, Seq: e.Seq}
		if err := applyBinding(ctx, tx, b, e.Body); err != nil {
			return err
		}
	case e.Kind == KindCheckpoint:
		cp, err := decodeCheckpoint(e.Body)
		if err != nil {
			return err
		}
		if err := applyCheckpoint(ctx, tx, cp, e.Origin, e.Seq); err != nil {
			return err
		}
	default:
		var h observationHeader
		if err := decodeEnvelopePayload(e.Body, &h); err != nil {
			return err
		}
		identity = h.Identity
	}
	if err := s.insert(ctx, tx, e.Origin, e.Seq, e.Kind, identity, epoch, e.Hash, e.Body, e.Sig); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if AlwaysIngest(e.Kind) || e.Kind == KindCheckpoint {
		s.projection.Add(1)
	}
	return nil
}

// RaiseCoverage implements replication.Store. Raising the coverage of the
// own origin also raises the sequence counter, so that a rebuilt instance
// never reuses a sequence number its peers know. The replicator calls it
// only on a pull, with values up to replication.MaxSeq.
func (s *Store) RaiseCoverage(ctx context.Context, cov map[string]int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	for origin, n := range cov {
		if err := advanceCoverage(ctx, tx, origin, n); err != nil {
			return err
		}
		if origin == s.origin {
			c, err := s.coverageTx(ctx, tx, origin)
			if err != nil {
				return err
			}
			if err := raiseMetaInt(ctx, tx, "next_seq", c+1); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) coverageTx(ctx context.Context, tx *sql.Tx, origin string) (int64, error) {
	var c int64
	err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT seq FROM coverage WHERE origin = ?), 0)`, origin).Scan(&c)
	return c, err
}

// Cursor implements replication.Store.
func (s *Store) Cursor(ctx context.Context, peer string) (int64, error) {
	var c int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE((SELECT pos FROM peer_cursor WHERE peer = ?), 0)`, peer).Scan(&c)
	return c, err
}

// SetCursor implements replication.Store. A cursor only moves forward.
func (s *Store) SetCursor(ctx context.Context, peer string, pos int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `INSERT INTO peer_cursor (peer, pos) VALUES (?, ?)
		ON CONFLICT (peer) DO UPDATE SET pos = MAX(pos, excluded.pos)`, peer, pos)
	return err
}

// Outbox implements replication.Store.
func (s *Store) Outbox(ctx context.Context, after int64) (int64, time.Time, error) {
	var n int64
	var oldest sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), MIN(recorded_at) FROM events WHERE pos > ?`, after).Scan(&n, &oldest); err != nil {
		return 0, time.Time{}, err
	}
	var t time.Time
	if oldest.Valid {
		t, _ = time.Parse(time.RFC3339Nano, oldest.String)
	}
	return n, t, nil
}

// Latest implements replication.Store.
func (s *Store) Latest(ctx context.Context, origin, kind string) ([]replication.Stored, error) {
	return s.storedEvents(ctx, `WHERE origin = ? AND kind = ? ORDER BY seq DESC`, origin, kind)
}

// SetFrontier implements replication.Store. The frontier only rises; a
// trigger refuses to lower it.
func (s *Store) SetFrontier(ctx context.Context, cp replication.Stored, frontier map[string]int64) error {
	if cp.Origin != s.origin || cp.Kind != KindCheckpoint {
		return errors.New("journal: the frontier must come from an own checkpoint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	for origin, n := range frontier {
		if _, err := tx.ExecContext(ctx, `INSERT INTO compaction (origin, seq) VALUES (?, ?)
			ON CONFLICT (origin) DO UPDATE SET seq = MAX(seq, excluded.seq)`, origin, n); err != nil {
			return err
		}
	}
	if err := raiseMetaInt(ctx, tx, "frontier_pos", cp.Pos); err != nil {
		return err
	}
	return tx.Commit()
}

func decodeEnvelopePayload(body []byte, v any) error {
	var env protocol.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return err
	}
	return env.Decode(v)
}
