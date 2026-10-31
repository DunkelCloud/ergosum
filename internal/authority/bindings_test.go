package authority

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/DunkelCloud/ergosum/internal/journal"
	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// newTestAuthority creates an unsealed instance whose bindings admins sign,
// without starting its listeners.
func newTestAuthority(t *testing.T, admins *jt.Admins) *Authority {
	t.Helper()
	dir := t.TempDir()
	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	data, err := keys.MarshalPrivatePEM(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Instance: "authority-a", TrustDomain: "example.com", Issuer: "https://ergosum.example.com",
		SigningKey: filepath.Join(dir, "signing.key"), Journal: filepath.Join(dir, "journal.db"),
		Listen: "100.64.0.10:7432", Registry: admins.Registry(1),
	}
	if err := os.WriteFile(cfg.SigningKey, data, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, Options{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// TestBindingListCache: the list endpoint reads the projection once per
// change, however many ask, and never answers with an older list.
func TestBindingListCache(t *testing.T) {
	admins := jt.NewAdmins(t, "alice")
	a := newTestAuthority(t, admins)
	h := a.apiHandler()
	get := func() int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, protocol.PathBindings, http.NoBody))
		var l journal.BindingList
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &l) != nil || l.Validate() != nil {
			t.Errorf("list: %d %s", rec.Code, rec.Body)
		}
		return len(l.Bindings)
	}

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { get() })
	}
	wg.Wait()
	if a.lists.builds != 1 {
		t.Fatalf("20 requests built the list %d times", a.lists.builds)
	}

	key, _ := keys.Generate()
	e := admins.Sign(t, jt.Set("example.com", "host1.example.com", 1, keys.Fingerprint(&key.PublicKey),
		journal.Check{Type: protocol.CheckTailnet, Target: "host1.example.ts.net"}), "alice")
	if _, err := a.store.AppendBinding(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if n := get(); n != 1 {
		t.Fatalf("%d bindings after a write", n)
	}
	get()
	if a.lists.builds != 2 {
		t.Fatalf("built %d times, want 2", a.lists.builds)
	}
}
