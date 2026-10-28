package journal_test

import (
	"context"
	"crypto/dsa" //nolint:staticcheck // DSA is used only to assert that it is rejected
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/DunkelCloud/ergosum/internal/journal"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

const td = "example.com"

func newStore(t *testing.T, admins *jt.Admins, threshold int) *journal.Store {
	t.Helper()
	return openInstance(t, admins, threshold, "instance-a", newKey(t))
}

// openInstance opens a journal for an instance and gives it its key.
func openInstance(t *testing.T, admins *jt.Admins, threshold int, name string, key *ecdsa.PrivateKey) *journal.Store {
	t.Helper()
	reg, err := journal.NewRegistry(admins.Registry(threshold))
	if err != nil {
		t.Fatal(err)
	}
	s, err := journal.Open(filepath.Join(t.TempDir(), "journal.db"), name, td, reg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.SetSigner(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	s.SetInstanceKeys(map[string]*ecdsa.PublicKey{name: &key.PublicKey})
	return s
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fingerprint(t *testing.T) string {
	k, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return keys.Fingerprint(&k.PublicKey)
}

var (
	tailnet = journal.Check{Type: "tailnet", Target: "host1.tailnet.example.com"}
	ipCheck = journal.Check{Type: "ip", Target: "192.0.2.10"}
)

func TestCanonicalForm(t *testing.T) {
	e := jt.Set(td, "host1.example.com", 3, "SHA256:"+strings.Repeat("A", 43),
		journal.Check{Type: "tailnet", Target: "host1.tailnet.example.com"},
		journal.Check{Type: "net", Target: "198.51.100.0/24"})
	c, err := e.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := "ergosum binding v1\n" +
		"kind binding.set\n" +
		"trust-domain example.com\n" +
		"identity host1.example.com\n" +
		"epoch 3\n" +
		"key SHA256:" + strings.Repeat("A", 43) + "\n" +
		"check net 198.51.100.0/24\n" +
		"check tailnet host1.tailnet.example.com\n"
	if string(c) != want {
		t.Fatalf("canonical form:\n%s\nwant:\n%s", c, want)
	}
	r := jt.Revoke(td, "host1.example.com", 4)
	c, _ = r.Canonical()
	if string(c) != "ergosum binding v1\nkind binding.revoked\ntrust-domain example.com\nidentity host1.example.com\nepoch 4\n" {
		t.Fatalf("revocation canonical form: %q", c)
	}
}

func TestValidation(t *testing.T) {
	fp := "SHA256:" + strings.Repeat("A", 43)
	bad := []*journal.BindingEvent{
		jt.Set(td, "Host1.example.com", 1, fp, tailnet),                                               // upper case
		jt.Set(td, "host1", 1, fp, tailnet),                                                           // single label
		jt.Set(td, "host1.example.com", 0, fp, tailnet),                                               // epoch 0
		jt.Set(td, "host1.example.com", 1, "SHA256:short", tailnet),                                   // fingerprint
		jt.Set(td, "host1.example.com", 1, fp),                                                        // no checks
		jt.Set(td, "host1.example.com", 1, fp, tailnet, tailnet),                                      // duplicate check
		jt.Set(td, "host1.example.com", 1, fp, journal.Check{Type: "net", Target: "198.51.100.1/24"}), // unmasked
		jt.Set(td, "host1.example.com", 1, fp, journal.Check{Type: "ip", Target: "127.0.0.1"}),        // loopback
		jt.Set(td, "host1.example.com", 1, fp, journal.Check{Type: "ip", Target: "host1.example.com"}),
		jt.Set(td, "host1.example.com", 1, fp, journal.Check{Type: "dns", Target: "host1.example.com"}),
		jt.Set(td, "host1.example.com\nkind binding.revoked", 1, fp, tailnet), // line injection
		jt.Set(td, "host1.example.com", 1, fp, journal.Check{Type: "tailnet", Target: "a.example.com\ncheck ip 192.0.2.1"}),
		jt.Set(td, "host1.example.com", 1, fp, journal.Check{Type: "ip", Target: "2001:DB8::10"}),        // not canonical
		jt.Set(td, "host1.example.com", 1, fp, journal.Check{Type: "ip", Target: "[2001:DB8::10]:7433"}), // not canonical
		jt.Set(td, "host1.example.com", 1, fp, journal.Check{Type: "tailnet", Target: "100.64.0.5"}),     // an address, not a name
		jt.Set("192.0.2.1", "host1.example.com", 1, fp, tailnet),                                         // trust domain is an address
	}
	for i, e := range bad {
		if err := e.Validate(); !errors.Is(err, journal.ErrInvalidEvent) {
			t.Errorf("case %d accepted: %v", i, err)
		}
	}
	good := jt.Set(td, "host1.example.com", 1, fp,
		journal.Check{Type: "ip", Target: "[2001:db8::10]:7433"},
		journal.Check{Type: "ip", Target: "203.0.113.7:7440"},
		journal.Check{Type: "net", Target: "2001:db8:1::/64"},
		journal.Check{Type: "tailnet", Target: "host1.tailnet.example.com:7433"})
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestApprovals(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice", "bob", "carol")
	s := newStore(t, admins, 2)
	fp := fingerprint(t)
	base := func(epoch uint64) *journal.BindingEvent {
		return jt.Set(td, "host1.example.com", epoch, fp, tailnet, ipCheck)
	}

	t.Run("without signature", func(t *testing.T) {
		if _, err := s.AppendBinding(ctx, base(1)); !errors.Is(err, journal.ErrBelowThreshold) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("forged signature", func(t *testing.T) {
		e := admins.Sign(t, base(1), "alice", "bob")
		e.Signatures[1] = strings.Replace(e.Signatures[1], "A", "B", 1)
		if _, err := s.AppendBinding(ctx, e); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("signature by a key outside the registry", func(t *testing.T) {
		outsider := jt.NewAdmins(t, "mallory")
		e := admins.Sign(t, base(1), "alice")
		e = outsider.Sign(t, e, "mallory")
		if _, err := s.AppendBinding(ctx, e); !errors.Is(err, journal.ErrUnknownSigner) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("below threshold", func(t *testing.T) {
		if _, err := s.AppendBinding(ctx, admins.Sign(t, base(1), "alice")); !errors.Is(err, journal.ErrBelowThreshold) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("same key counted twice", func(t *testing.T) {
		e := admins.Sign(t, base(1), "alice", "alice")
		if _, err := s.AppendBinding(ctx, e); !errors.Is(err, journal.ErrDuplicateSigner) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("signatures over different epochs", func(t *testing.T) {
		e := admins.Sign(t, base(2), "alice")
		e = admins.SignAs(t, e, base(1), "bob")
		if _, err := s.AppendBinding(ctx, e); !errors.Is(err, journal.ErrInvalidSignature) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("more signatures than keys", func(t *testing.T) {
		e := admins.Sign(t, base(1), "alice", "bob", "carol", "alice")
		if _, err := s.AppendBinding(ctx, e); !errors.Is(err, journal.ErrTooManySignatures) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("wrong trust domain", func(t *testing.T) {
		e := admins.Sign(t, jt.Set("other.example.com", "host1.example.com", 1, fp, tailnet), "alice", "bob")
		if _, err := s.AppendBinding(ctx, e); !errors.Is(err, journal.ErrTrustDomain) {
			t.Fatalf("got %v", err)
		}
	})
	if n, _ := s.Count(ctx, ""); n != 0 {
		t.Fatalf("rejected events left %d journal entries", n)
	}
	if b, _ := s.Binding(ctx, "host1.example.com"); b != nil {
		t.Fatal("rejected events reached the projection")
	}

	t.Run("threshold met", func(t *testing.T) {
		r, err := s.AppendBinding(ctx, admins.Sign(t, base(2), "alice", "carol"))
		if err != nil {
			t.Fatal(err)
		}
		if r.Seq != 1 || r.Origin != "instance-a" {
			t.Fatalf("receipt %+v", r)
		}
		b, _ := s.Binding(ctx, "host1.example.com")
		if !b.Active() || b.Epoch != 2 || b.Key != fp {
			t.Fatalf("projection %+v", b)
		}
	})
	t.Run("resubmission is idempotent", func(t *testing.T) {
		r, err := s.AppendBinding(ctx, admins.Sign(t, base(2), "bob", "carol"))
		if err != nil || !r.Duplicate || r.Seq != 1 {
			t.Fatalf("%+v %v", r, err)
		}
	})
	t.Run("lower epoch", func(t *testing.T) {
		if _, err := s.AppendBinding(ctx, admins.Sign(t, base(1), "alice", "bob")); !errors.Is(err, journal.ErrLowerEpoch) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestOrderingRule(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice")
	s := newStore(t, admins, 1)
	id := "host1.example.com"

	a := admins.Sign(t, jt.Set(td, id, 5, fingerprint(t), tailnet), "alice")
	b := admins.Sign(t, jt.Set(td, id, 5, fingerprint(t), tailnet), "alice")
	ha, _ := a.Hash()
	hb, _ := b.Hash()
	small, large := a, b
	if hb < ha {
		small, large = b, a
	}
	// The larger hash first, then the smaller one replaces it.
	if _, err := s.AppendBinding(ctx, large); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendBinding(ctx, small); err != nil {
		t.Fatal(err)
	}
	cur, _ := s.Binding(ctx, id)
	if cur.Key != small.Key {
		t.Fatal("same epoch: smaller hash did not win")
	}
	// Re-submitting the losing event is idempotent and changes nothing.
	again := admins.Sign(t, jt.Set(td, id, 5, large.Key, tailnet), "alice")
	if r, err := s.AppendBinding(ctx, again); err != nil || !r.Duplicate {
		t.Fatalf("resubmission: %+v %v", r, err)
	}
	if cur, _ = s.Binding(ctx, id); cur.Key != small.Key {
		t.Fatal("resubmitted loser changed the projection")
	}
	// A new same-epoch event with a larger hash than the current one is
	// rejected.
	for {
		c := admins.Sign(t, jt.Set(td, id, 5, fingerprint(t), tailnet), "alice")
		if h, _ := c.Hash(); h > cur.Hash {
			if _, err := s.AppendBinding(ctx, c); !errors.Is(err, journal.ErrSuperseded) {
				t.Fatalf("got %v", err)
			}
			break
		}
	}
	// A revocation at the same epoch wins over the binding.
	if _, err := s.AppendBinding(ctx, admins.Sign(t, jt.Revoke(td, id, 5), "alice")); err != nil {
		t.Fatal(err)
	}
	cur, _ = s.Binding(ctx, id)
	if cur.Active() {
		t.Fatal("same epoch: revocation did not win")
	}
	// A new binding at a higher epoch re-enrolls.
	if _, err := s.AppendBinding(ctx, admins.Sign(t, jt.Set(td, id, 6, fingerprint(t), tailnet), "alice")); err != nil {
		t.Fatal(err)
	}
	cur, _ = s.Binding(ctx, id)
	if !cur.Active() || cur.Epoch != 6 {
		t.Fatalf("re-enrollment: %+v", cur)
	}

	// The incremental projection equals a fold over the journal.
	ref, err := s.Project(ctx)
	if err != nil {
		t.Fatal(err)
	}
	all, _ := s.Bindings(ctx)
	if len(ref) != len(all) || ref[id].Hash != all[id].Hash {
		t.Fatalf("projection drift: %+v vs %+v", ref[id], all[id])
	}
}

func TestAppendOnly(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice")
	reg, _ := journal.NewRegistry(admins.Registry(1))
	path := filepath.Join(t.TempDir(), "journal.db")
	s, err := journal.Open(path, "instance-a", td, reg)
	if err != nil {
		t.Fatal(err)
	}
	ev := admins.Sign(t, jt.Set(td, "host1.example.com", 1, fingerprint(t), tailnet), "alice")
	if _, err := s.AppendBinding(ctx, ev); !errors.Is(err, journal.ErrNoSigner) {
		t.Fatalf("own event without the instance key: %v", err)
	}
	if err := s.SetSigner(ctx, newKey(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendBinding(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if err := journal.TamperForTest(s); err == nil {
		t.Fatal("UPDATE on the journal succeeded")
	}
	if err := journal.ResignForTest(s); err == nil {
		t.Fatal("an event was signed a second time")
	}
	s.Close()
	// Reopening with another trust domain or instance name is refused; the
	// original pair opens the journal again.
	if _, err := journal.Open(path, "instance-a", "other.example.com", reg); err == nil {
		t.Fatal("journal opened for another trust domain")
	}
	if _, err := journal.Open(path, "instance-b", td, reg); err == nil {
		t.Fatal("journal opened for another instance")
	}
	s, err = journal.Open(path, "instance-a", td, reg)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestRegistryValidation(t *testing.T) {
	admins := jt.NewAdmins(t, "alice", "bob")
	cfg := admins.Registry(3)
	if _, err := journal.NewRegistry(cfg); err == nil {
		t.Fatal("threshold above key count accepted")
	}
	cfg = admins.Registry(1)
	ap := cfg.Approvals[journal.KindBindingSet]
	ap.Keys = append(ap.Keys, "nobody")
	cfg.Approvals[journal.KindBindingSet] = ap
	if _, err := journal.NewRegistry(cfg); err == nil {
		t.Fatal("unknown admin accepted")
	}
	// Weak keys and certificates are no trust root.
	for name, line := range map[string]string{
		"dsa":         dsaKeyLine(t),
		"rsa-1024":    rsaKeyLine(t, 1024),
		"certificate": certLine(t, admins.Signers["alice"]),
	} {
		cfg := admins.Registry(1)
		cfg.Admins["weak"] = line
		if _, err := journal.NewRegistry(cfg); err == nil {
			t.Errorf("%s admin key accepted", name)
		}
	}
	cfg = admins.Registry(1)
	cfg.Admins["rsa"] = rsaKeyLine(t, 2048)
	if _, err := journal.NewRegistry(cfg); err != nil {
		t.Fatalf("2048-bit RSA admin key rejected: %v", err)
	}
}

func dsaKeyLine(t *testing.T) string {
	t.Helper()
	var priv dsa.PrivateKey                                                                      //nolint:staticcheck // see the import
	if err := dsa.GenerateParameters(&priv.Parameters, rand.Reader, dsa.L1024N160); err != nil { //nolint:staticcheck // see the import
		t.Fatal(err)
	}
	if err := dsa.GenerateKey(&priv, rand.Reader); err != nil { //nolint:staticcheck // see the import
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(pub))
}

func rsaKeyLine(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(pub))
}

func certLine(t *testing.T, signer ssh.Signer) string {
	t.Helper()
	cert := &ssh.Certificate{Key: signer.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(cert))
}

// TestMigrationFromV1: a journal of schema version 1 is migrated on open
// without changing its events; positions, the sequence counter and the
// coverage follow from them.
func TestMigrationFromV1(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice")
	reg, _ := journal.NewRegistry(admins.Registry(1))
	path := filepath.Join(t.TempDir(), "journal.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	ev := admins.Sign(t, jt.Set(td, "host1.example.com", 1, fingerprint(t), tailnet), "alice")
	body, _ := json.Marshal(ev)
	h, _ := ev.Hash()
	stmts := []string{
		`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		journal.SchemaV1,
		`INSERT INTO meta (key, value) VALUES ('schema_version', '1'), ('trust_domain', 'example.com'), ('instance', 'instance-a')`,
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	for seq, kind := range []string{"binding.set", "observation.issued", "observation.issued"} {
		b, hh := body, h
		if kind != "binding.set" {
			b, hh = []byte(`{"payload":"e30","signature":""}`), strings.Repeat(strconv.Itoa(seq), 64)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO events (origin, seq, kind, identity, epoch, hash, body, recorded_at) VALUES ('instance-a', ?, ?, 'host1.example.com', 0, ?, ?, '2026-10-27T00:00:00Z')`,
			seq+1, kind, hh, b); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO bindings (identity, kind, epoch, key, checks, hash, origin, seq) VALUES ('host1.example.com', 'binding.set', 1, ?, ?, ?, 'instance-a', 1)`,
		ev.Key, `[{"type":"tailnet","target":"host1.tailnet.example.com"}]`, h); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := journal.Open(path, "instance-a", td, reg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st, err := s.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Events != 3 || st.NextSeq != 4 || st.Coverage["instance-a"] != 3 || st.Bindings != 1 {
		t.Fatalf("migrated state: %+v", st)
	}
	_, events, last, err := s.Read(ctx, 0, 10)
	if err != nil || len(events) != 3 || last != 3 || events[0].Seq != 1 || events[2].Pos != 3 {
		t.Fatalf("positions after migration: %+v, %d, %v", events, last, err)
	}
	// The events of version 1 are signed once the key is there.
	key := newKey(t)
	if err := s.SetSigner(ctx, key); err != nil {
		t.Fatal(err)
	}
	_, events, _, _ = s.Read(ctx, 0, 10)
	for _, e := range events {
		if !keys.Verify(&key.PublicKey, protocol.ContextEvent, e.SigningInput(), e.Sig) {
			t.Fatalf("migrated event %d not signed", e.Seq)
		}
	}
	// The projection carries the winning event, ready for a checkpoint.
	if _, err := s.WriteCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if err := journal.TamperForTest(s); err == nil {
		t.Fatal("history rewritten after the migration")
	}
}

// TestDeleteTriggerAndSequence: nothing above the compaction frontier can
// be deleted, and sequence numbers are never reused, also when the newest
// event is gone.
func TestDeleteTriggerAndSequence(t *testing.T) {
	ctx := context.Background()
	admins := jt.NewAdmins(t, "alice")
	s := newStore(t, admins, 1)
	for i := uint64(1); i <= 3; i++ {
		if _, err := s.AppendBinding(ctx, admins.Sign(t, jt.Set(td, "host1.example.com", i, fingerprint(t), tailnet), "alice")); err != nil {
			t.Fatal(err)
		}
	}
	if err := journal.DeleteForTest(s, "instance-a", 1); err == nil {
		t.Fatal("deleted without a frontier")
	}
	if err := journal.SetFrontierForTest(s, "instance-a", 2); err != nil {
		t.Fatal(err)
	}
	if err := journal.DeleteForTest(s, "instance-a", 3); err == nil {
		t.Fatal("deleted above the frontier")
	}
	if err := journal.SetFrontierForTest(s, "instance-a", 1); err == nil {
		t.Fatal("lowered the frontier")
	}
	if err := journal.SetFrontierForTest(s, "instance-a", 3); err != nil {
		t.Fatal(err)
	}
	if err := journal.DeleteForTest(s, "instance-a", 3); err != nil {
		t.Fatal(err)
	}
	r, err := s.AppendBinding(ctx, admins.Sign(t, jt.Revoke(td, "host1.example.com", 4), "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Seq != 4 {
		t.Fatalf("sequence number %d after deleting the newest event, want 4", r.Seq)
	}
}
