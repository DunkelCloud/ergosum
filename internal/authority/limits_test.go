package authority

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

func validConfig(t *testing.T) Config {
	t.Helper()
	cfg := Config{
		Instance: "authority-a", TrustDomain: "example.com", Issuer: "https://ergosum.example.com",
		SigningKey: "signing.key", Listen: "100.64.0.10:7432", Registry: jt.NewAdmins(t, "alice").Registry(1),
	}
	cfg.SetDefaults()
	return cfg
}

func TestValidateRanges(t *testing.T) {
	good := validConfig(t)
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*Config){
		"negative clock_skew":       func(c *Config) { c.ClockSkew = -2 * time.Minute },
		"huge clock_skew":           func(c *Config) { c.ClockSkew = 2 * time.Hour },
		"callback port too high":    func(c *Config) { c.Callbacks.Port = 70000 },
		"negative callback port":    func(c *Config) { c.Callbacks.Port = -1 },
		"negative callback timeout": func(c *Config) { c.Callbacks.Timeout = -time.Second },
		"token_ttl too short":       func(c *Config) { c.TokenTTL = time.Second },
	}
	for name, mutate := range bad {
		c := validConfig(t)
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestValidateListen(t *testing.T) {
	cases := []struct {
		listen string
		all    bool
		ok     bool
	}{
		{"", false, false},
		{":7432", false, false},
		{"0.0.0.0:7432", false, false},
		{"[::]:7432", false, false},
		{"7432", false, false},
		{"100.64.0.10:7432", false, true},
		{"[fd7a:115c:a1e0::10]:7432", false, true},
		{"authority-a.example.com:7432", false, true},
		{":7432", true, true},
		{"0.0.0.0:7432", true, true},
	}
	for _, c := range cases {
		cfg := Config{Listen: c.listen, ListenAllInterfaces: c.all}
		if err := cfg.validateListen("listen", cfg.Listen, 7432); (err == nil) != c.ok {
			t.Errorf("listen %q (all interfaces %v): err = %v, want ok = %v", c.listen, c.all, err, c.ok)
		}
	}
}

func TestReplayCache(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := newReplayCache(4 * time.Minute)
	if !c.first("host1.example.com id", now) {
		t.Fatal("new key refused")
	}
	if c.first("host1.example.com id", now.Add(3*time.Minute)) {
		t.Fatal("repeated key accepted within the window")
	}
	if !c.first("host2.example.com id", now) {
		t.Fatal("same request ID for another identity refused")
	}
	if !c.first("host1.example.com id", now.Add(5*time.Minute)) {
		t.Fatal("key still refused after the window")
	}
}

func TestWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	w := &window{every: time.Minute, max: 3}
	for i := 0; i < 3; i++ {
		if !w.allow(now) {
			t.Fatalf("event %d refused", i)
		}
	}
	if w.allow(now.Add(30 * time.Second)) {
		t.Fatal("fourth event in the window allowed")
	}
	if !w.allow(now.Add(time.Minute)) {
		t.Fatal("new window refused")
	}
}

// "No open request" proves a second key only from a daemon that ran when the
// request was made; "ended" and a later process start prove nothing.
func TestClassify(t *testing.T) {
	requested := time.Unix(1_800_000_000, 0)
	before := requested.Add(-time.Hour)
	for _, c := range []struct {
		status  string
		started time.Time
		want    string
	}{
		{protocol.StatusConfirmed, before, OutcomeConfirmed},
		{protocol.StatusNoOpenRequest, before, OutcomeNoOpenRequest},
		{protocol.StatusNoOpenRequest, requested.Add(time.Second), OutcomeEnded},
		{protocol.StatusNoOpenRequest, time.Time{}, OutcomeEnded},
		{protocol.StatusEnded, before, OutcomeEnded},
		{"maybe", before, OutcomeInvalidResponse},
	} {
		got, _ := classify(protocol.CallbackResponse{Status: c.status, Started: c.started}, requested)
		if got != c.want {
			t.Errorf("%s started %s: %s, want %s", c.status, c.started, got, c.want)
		}
	}
}

// A retired instance keeps its key for verifying history but has no URL.
func TestRetiredPeer(t *testing.T) {
	cfg := validConfig(t)
	k, _ := keys.Generate()
	pem := string(keys.MarshalPublicPEM(&k.PublicKey))
	cfg.Replication.Peers = []PeerConfig{{Name: "old", Key: pem, Retired: true, URL: "https://192.0.2.9:7435"}}
	if _, err := cfg.peers(); err == nil {
		t.Fatal("a retired instance with a URL was accepted")
	}
	cfg.Replication.Peers[0].URL = ""
	ps, err := cfg.peers()
	if err != nil || len(ps) != 1 || !ps[0].retired {
		t.Fatalf("retired instance: %+v %v", ps, err)
	}
}

// TestKeyMode: a signing key that other users may read or change is
// refused; 0600 and 0640 are fine.
func TestKeyMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits on Windows")
	}
	path := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(path, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for mode, ok := range map[os.FileMode]bool{0o600: true, 0o640: true, 0o400: true, 0o644: false, 0o660: false, 0o604: false, 0o606: false} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkKeyMode(path); (err == nil) != ok {
			t.Errorf("mode %04o: %v", mode, err)
		}
	}
}

// TestIdentityLimit: one request of an identity at a time, a burst, then one
// per interval; other identities are not affected.
func TestIdentityLimit(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newIdentityLimit(3, time.Minute)
	release, ok := l.acquire("host1", now)
	if !ok {
		t.Fatal("first request refused")
	}
	if _, ok := l.acquire("host1", now); ok {
		t.Fatal("second request in flight admitted")
	}
	if r, ok := l.acquire("host2", now); !ok {
		t.Fatal("another identity refused")
	} else {
		r()
	}
	release()
	for i := 1; i < 3; i++ {
		r, ok := l.acquire("host1", now)
		if !ok {
			t.Fatalf("request %d of the burst refused", i+1)
		}
		r()
	}
	if _, ok := l.acquire("host1", now.Add(30*time.Second)); ok {
		t.Fatal("request beyond the burst admitted")
	}
	r, ok := l.acquire("host1", now.Add(time.Minute))
	if !ok {
		t.Fatal("request after an interval refused")
	}
	r()
	if _, ok := l.acquire("host1", now.Add(time.Minute)); ok {
		t.Fatal("second request after one interval admitted")
	}
	// Idle identities are forgotten once their rate is restored.
	l.acquire("host3", now.Add(10*time.Minute))
	if len(l.ids) != 1 {
		t.Fatalf("%d identities kept", len(l.ids))
	}
}
