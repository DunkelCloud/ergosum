package journal

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
