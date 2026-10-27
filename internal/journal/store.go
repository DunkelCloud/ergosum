package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no cgo
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
	origin      TEXT    NOT NULL,
	seq         INTEGER NOT NULL,
	kind        TEXT    NOT NULL,
	identity    TEXT    NOT NULL,
	epoch       INTEGER NOT NULL DEFAULT 0,
	hash        TEXT    NOT NULL,
	body        BLOB    NOT NULL,
	recorded_at TEXT    NOT NULL,
	PRIMARY KEY (origin, seq)
);
CREATE INDEX IF NOT EXISTS events_identity ON events (identity, epoch);
CREATE UNIQUE INDEX IF NOT EXISTS events_binding_hash ON events (hash) WHERE kind LIKE 'binding.%';
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
	BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
	BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
CREATE TABLE IF NOT EXISTS bindings (
	identity TEXT PRIMARY KEY,
	kind     TEXT    NOT NULL,
	epoch    INTEGER NOT NULL,
	key      TEXT    NOT NULL,
	checks   TEXT    NOT NULL,
	hash     TEXT    NOT NULL,
	origin   TEXT    NOT NULL,
	seq      INTEGER NOT NULL
);
`

const schemaVersion = "1"

// Store is the SQLite-backed journal of one authority instance.
type Store struct {
	db          *sql.DB
	origin      string
	trustDomain string
	registry    *Registry
	mu          sync.Mutex // serializes read-modify-write of the projection
	now         func() time.Time
}

// Open opens (and creates) the journal at path. origin names this instance
// in the journal; trustDomain must match every binding event.
func Open(path, origin, trustDomain string, registry *Registry) (*Store, error) {
	if origin == "" {
		return nil, errors.New("journal: empty origin")
	}
	q := url.Values{}
	for _, p := range []string{"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)", "foreign_keys(1)"} {
		q.Add("_pragma", p)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; reads are cheap
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("journal: schema: %w", err)
	}
	var v string
	err = db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&v)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := db.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES ('schema_version', ?), ('trust_domain', ?)`, schemaVersion, trustDomain); err != nil {
			_ = db.Close()
			return nil, err
		}
	case err != nil:
		_ = db.Close()
		return nil, err
	case v != schemaVersion:
		_ = db.Close()
		return nil, fmt.Errorf("journal: schema version %s, expected %s", v, schemaVersion)
	default:
		var td string
		if err := db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'trust_domain'`).Scan(&td); err != nil || td != trustDomain {
			_ = db.Close()
			return nil, fmt.Errorf("journal: belongs to trust domain %q, configured %q", td, trustDomain)
		}
	}
	return &Store{db: db, origin: origin, trustDomain: trustDomain, registry: registry, now: time.Now}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Binding is the projected current state of one identity.
type Binding struct {
	Identity string  `json:"identity"`
	Kind     string  `json:"kind"`
	Epoch    uint64  `json:"epoch"`
	Key      string  `json:"key,omitempty"`
	Checks   []Check `json:"checks,omitempty"`
	Hash     string  `json:"hash"`
	Origin   string  `json:"origin"`
	Seq      int64   `json:"seq"`
}

// Active reports whether the binding allows issuance.
func (b *Binding) Active() bool { return b != nil && b.Kind == KindBindingSet }

// Receipt describes where an event was recorded.
type Receipt struct {
	Origin    string `json:"origin"`
	Seq       int64  `json:"seq"`
	Hash      string `json:"hash"`
	Duplicate bool   `json:"duplicate,omitempty"`
}

// Errors returned by AppendBinding besides the registry errors.
var (
	ErrTrustDomain = errors.New("event belongs to another trust domain")
	ErrLowerEpoch  = errors.New("epoch is lower than the current binding")
	ErrSuperseded  = errors.New("an event with the same epoch takes precedence")
)

// AppendBinding verifies an admin-signed binding event against the registry
// and the ordering rule and appends it. Events that would not change the
// projection are rejected rather than recorded. Re-submitting an accepted
// event is idempotent.
func (s *Store) AppendBinding(ctx context.Context, e *BindingEvent) (Receipt, error) {
	if err := e.Validate(); err != nil {
		return Receipt{}, err
	}
	if e.TrustDomain != s.trustDomain {
		return Receipt{}, fmt.Errorf("%w: %q", ErrTrustDomain, e.TrustDomain)
	}
	if _, err := s.registry.Verify(e); err != nil {
		return Receipt{}, err
	}
	hash, err := e.Hash()
	if err != nil {
		return Receipt{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var r Receipt
	err = s.db.QueryRowContext(ctx, `SELECT origin, seq, hash FROM events WHERE hash = ? AND kind LIKE 'binding.%'`, hash).Scan(&r.Origin, &r.Seq, &r.Hash)
	if err == nil {
		r.Duplicate = true
		return r, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, err
	}

	cur, err := s.Binding(ctx, e.Identity)
	if err != nil {
		return Receipt{}, err
	}
	cand := &Binding{Identity: e.Identity, Kind: e.Kind, Epoch: e.Epoch, Key: e.Key, Checks: e.SortedChecks(), Hash: hash}
	if cur != nil {
		if e.Epoch < cur.Epoch {
			return Receipt{}, fmt.Errorf("%w: %d < %d", ErrLowerEpoch, e.Epoch, cur.Epoch)
		}
		if !Wins(cand, cur) {
			return Receipt{}, fmt.Errorf("%w: epoch %d", ErrSuperseded, e.Epoch)
		}
	}
	body, err := json.Marshal(e)
	if err != nil {
		return Receipt{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	seq, err := s.insert(ctx, tx, e.Kind, e.Identity, e.Epoch, hash, body)
	if err != nil {
		return Receipt{}, err
	}
	cand.Origin, cand.Seq = s.origin, seq
	if err := upsertBinding(ctx, tx, cand); err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return Receipt{Origin: s.origin, Seq: seq, Hash: hash}, nil
}

// Wins reports whether binding a takes precedence over b: the higher epoch
// wins; at equal epochs a revocation wins, otherwise the smaller hash.
func Wins(a, b *Binding) bool {
	if a.Epoch != b.Epoch {
		return a.Epoch > b.Epoch
	}
	ar, br := a.Kind == KindBindingRevoked, b.Kind == KindBindingRevoked
	if ar != br {
		return ar
	}
	return a.Hash < b.Hash
}

func (s *Store) insert(ctx context.Context, tx *sql.Tx, kind, identity string, epoch uint64, hash string, body []byte) (int64, error) {
	var seq int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE origin = ?`, s.origin).Scan(&seq); err != nil {
		return 0, err
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO events (origin, seq, kind, identity, epoch, hash, body, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		s.origin, seq, kind, identity, epoch, hash, body, s.now().UTC().Format(time.RFC3339Nano))
	return seq, err
}

func upsertBinding(ctx context.Context, tx *sql.Tx, b *Binding) error {
	checks, err := json.Marshal(b.Checks)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO bindings (identity, kind, epoch, key, checks, hash, origin, seq)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (identity) DO UPDATE SET
			kind = excluded.kind, epoch = excluded.epoch, key = excluded.key,
			checks = excluded.checks, hash = excluded.hash,
			origin = excluded.origin, seq = excluded.seq`,
		b.Identity, b.Kind, b.Epoch, b.Key, string(checks), b.Hash, b.Origin, b.Seq)
	return err
}

// Binding returns the projected binding of identity, or nil.
func (s *Store) Binding(ctx context.Context, identity string) (*Binding, error) {
	var b Binding
	var checks string
	err := s.db.QueryRowContext(ctx,
		`SELECT identity, kind, epoch, key, checks, hash, origin, seq FROM bindings WHERE identity = ?`, identity).
		Scan(&b.Identity, &b.Kind, &b.Epoch, &b.Key, &checks, &b.Hash, &b.Origin, &b.Seq)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(checks), &b.Checks); err != nil {
		return nil, err
	}
	return &b, nil
}

// AppendObservation records an instance-signed observation. body is the
// JSON of a signed envelope.
func (s *Store) AppendObservation(ctx context.Context, kind, identity, hash string, body []byte) (Receipt, error) {
	if !strings.HasPrefix(kind, KindObservation+".") {
		return Receipt{}, fmt.Errorf("journal: %q is not an observation kind", kind)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	seq, err := s.insert(ctx, tx, kind, identity, 0, hash, body)
	if err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return Receipt{Origin: s.origin, Seq: seq, Hash: hash}, nil
}

// Count returns the number of events of a kind (or of all kinds for "").
func (s *Store) Count(ctx context.Context, kind string) (int, error) {
	var n int
	var err error
	if kind == "" {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE kind = ?`, kind).Scan(&n)
	}
	return n, err
}

// Project recomputes the projection from the binding events alone, without
// touching the stored projection. It is the reference against which the
// incrementally maintained projection can be checked.
func (s *Store) Project(ctx context.Context) (map[string]*Binding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT origin, seq, body FROM events WHERE kind LIKE 'binding.%' ORDER BY recorded_at, origin, seq`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]*Binding{}
	for rows.Next() {
		var origin string
		var seq int64
		var body []byte
		if err := rows.Scan(&origin, &seq, &body); err != nil {
			return nil, err
		}
		var e BindingEvent
		if err := json.Unmarshal(body, &e); err != nil {
			return nil, fmt.Errorf("journal: event %s/%d: %w", origin, seq, err)
		}
		h, err := e.Hash()
		if err != nil {
			return nil, err
		}
		b := &Binding{Identity: e.Identity, Kind: e.Kind, Epoch: e.Epoch, Key: e.Key, Checks: e.SortedChecks(), Hash: h, Origin: origin, Seq: seq}
		if cur := out[e.Identity]; cur == nil || Wins(b, cur) {
			out[e.Identity] = b
		}
	}
	return out, rows.Err()
}

// Bindings returns the stored projection of all identities.
func (s *Store) Bindings(ctx context.Context) (map[string]*Binding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT identity FROM bindings`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	out := map[string]*Binding{}
	for _, id := range ids {
		b, err := s.Binding(ctx, id)
		if err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, nil
}

// EventBodies returns the stored bodies of all events of a kind, in journal
// order.
func (s *Store) EventBodies(ctx context.Context, kind string) ([][]byte, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT body FROM events WHERE kind = ? ORDER BY recorded_at, origin, seq`, kind)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
