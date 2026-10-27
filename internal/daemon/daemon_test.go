package daemon

import (
	"path/filepath"
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

func TestRequestBook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.json")
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	b, err := loadRequestBook(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	id, err := b.open()
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := b.open(); again != id {
		t.Fatal("open request not reused")
	}
	// A restart reloads the open request.
	b2, _ := loadRequestBook(path, clock)
	if again, _ := b2.open(); again != id {
		t.Fatal("open request lost across restart")
	}
	if !b2.known(id) || b2.known("AAAAAAAAAAAAAAAAAAAAAA") {
		t.Fatal("known() wrong")
	}
	if err := b2.complete(id); err != nil {
		t.Fatal(err)
	}
	now = now.Add(9 * time.Minute)
	if !b2.known(id) {
		t.Fatal("completed request forgotten before ten minutes")
	}
	if next, _ := b2.open(); next == id {
		t.Fatal("completed request ID reused")
	}
	now = now.Add(2 * time.Minute)
	if b2.known(id) {
		t.Fatal("completed request still known after ten minutes")
	}
	// An open request is abandoned after MaxOpen and gets a new ID.
	stale, _ := b2.open()
	now = now.Add(MaxOpen + time.Second)
	if fresh, _ := b2.open(); fresh == stale {
		t.Fatal("stale open request reused")
	}
	if !b2.known(stale) {
		t.Fatal("abandoned request forgotten immediately")
	}
}
