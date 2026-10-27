package journal_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DunkelCloud/ergosum/internal/journal"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/keys"
)

const td = "example.com"

func newStore(t *testing.T, admins *jt.Admins, threshold int) *journal.Store {
	t.Helper()
	reg, err := journal.NewRegistry(admins.Registry(threshold))
	if err != nil {
		t.Fatal(err)
	}
	s, err := journal.Open(filepath.Join(t.TempDir(), "journal.db"), "instance-a", td, reg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
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
	if _, err := s.AppendBinding(ctx, admins.Sign(t, jt.Set(td, "host1.example.com", 1, fingerprint(t), tailnet), "alice")); err != nil {
		t.Fatal(err)
	}
	if err := journal.TamperForTest(s); err == nil {
		t.Fatal("UPDATE on the journal succeeded")
	}
	s.Close()
	// Reopening with another trust domain is refused.
	if _, err := journal.Open(path, "instance-a", "other.example.com", reg); err == nil {
		t.Fatal("journal opened for another trust domain")
	}
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
}
