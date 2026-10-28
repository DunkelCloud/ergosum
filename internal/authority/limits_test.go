package authority

import (
	"testing"
	"time"

	jt "github.com/DunkelCloud/ergosum/internal/journal/journaltest"
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
