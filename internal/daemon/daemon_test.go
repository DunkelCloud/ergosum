package daemon

import (
	"testing"
	"time"

	"github.com/DunkelCloud/ergosum/internal/jwt"
)

func TestRenewDelay(t *testing.T) {
	iat := time.Unix(1_800_000_000, 0)
	c := jwt.Claims{IssuedAt: iat.Unix(), Expiry: iat.Add(30 * time.Minute).Unix()}
	for i := 0; i < 1000; i++ {
		d := renewDelay(c, iat)
		if d < 12*time.Minute || d > 18*time.Minute {
			t.Fatalf("renewal after %s, want 12m..18m", d)
		}
	}
	// Overdue renewals happen right away.
	if d := renewDelay(c, iat.Add(29*time.Minute)); d != time.Second {
		t.Fatalf("overdue: %s", d)
	}
}

func TestBackoff(t *testing.T) {
	b := backoff{base: 5 * time.Second, max: 5 * time.Minute}
	for i := 0; i < 20; i++ {
		if d := b.next(); d < time.Second || d > 5*time.Minute {
			t.Fatalf("attempt %d: %s", i, d)
		}
	}
}

func TestInflight(t *testing.T) {
	const a, b = "SHA256:authority-a", "SHA256:authority-b"
	f := newInflight()
	id := "AAAAAAAAAAAAAAAAAAAAAA"
	if f.confirms(id, a) {
		t.Fatal("unknown request confirmed")
	}
	f.add(id, a)
	if !f.confirms(id, a) {
		t.Fatal("request in flight not confirmed")
	}
	// The same request ID from another instance is not ours.
	if f.confirms(id, b) {
		t.Fatal("request confirmed for an instance it was not sent to")
	}
	f.remove(id)
	if f.confirms(id, a) {
		t.Fatal("finished request still confirmed")
	}
}
