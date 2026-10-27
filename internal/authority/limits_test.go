package authority

import (
	"testing"
	"time"
)

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
		if err := cfg.validateListen(); (err == nil) != c.ok {
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
