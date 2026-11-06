package journal

import "context"

// SchemaV1 is the schema of version 1, for migration tests.
const SchemaV1 = schemaV1

// TamperForTest tries to rewrite history; the append-only triggers must
// refuse it.
func TamperForTest(s *Store) error {
	_, err := s.db.Exec(`UPDATE events SET identity = 'other.example.com'`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM events`)
	return err
}

// ResignForTest tries to replace the signatures of all events; the
// triggers allow a signature to be set only once.
func ResignForTest(s *Store) error {
	_, err := s.db.Exec(`UPDATE events SET sig = x'00'`)
	return err
}

// DeleteForTest deletes one event directly, past every check but the
// delete trigger.
func DeleteForTest(s *Store, origin string, seq int64) error {
	_, err := s.db.ExecContext(context.Background(), `DELETE FROM events WHERE origin = ? AND seq = ?`, origin, seq)
	return err
}

// SetMaxUncoveredForTest lowers MaxUncovered for one store.
func SetMaxUncoveredForTest(s *Store, n int) { s.maxUncovered = n }

// TempStoreForTest returns the temp_store setting of the connection: 2 is
// MEMORY.
func TempStoreForTest(s *Store) (int, error) {
	var v int
	err := s.db.QueryRowContext(context.Background(), `PRAGMA temp_store`).Scan(&v)
	return v, err
}

// SetFrontierForTest raises the compaction frontier of an origin directly.
func SetFrontierForTest(s *Store, origin string, seq int64) error {
	_, err := s.db.ExecContext(context.Background(), `INSERT INTO compaction (origin, seq) VALUES (?, ?)
		ON CONFLICT (origin) DO UPDATE SET seq = excluded.seq`, origin, seq)
	return err
}
