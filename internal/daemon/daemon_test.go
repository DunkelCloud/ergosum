package daemon

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/DunkelCloud/ergosum/internal/jwt"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

func TestPickAddresses(t *testing.T) {
	var cands []ifaceAddr
	for i := 0; i < 20; i++ {
		cands = append(cands, ifaceAddr{addr: fmt.Sprintf("172.18.%d.1", i), iface: "br-" + strconv.Itoa(i), index: 1 + i})
	}
	cands = append(cands,
		ifaceAddr{addr: "198.51.100.20", iface: "eth0", index: 30},
		ifaceAddr{addr: "2001:db8::20", iface: "eth0", index: 30},
		ifaceAddr{addr: "198.51.100.20", iface: "eth0.100", index: 31}, // the same address again
	)
	out, truncated := pickAddresses(cands)
	if !truncated || len(out) != protocol.MaxAddresses {
		t.Fatalf("%d addresses, truncated=%v", len(out), truncated)
	}
	if out[0] != "198.51.100.20" || out[1] != "2001:db8::20" {
		t.Fatalf("physical interface not first: %v", out[:2])
	}
	for _, a := range out[2:] {
		if a == "198.51.100.20" {
			t.Fatal("duplicate address reported")
		}
	}
	short := []ifaceAddr{{addr: "192.0.2.1", iface: "eth0", index: 2}, {addr: "172.17.0.1", iface: "docker0", index: 1}}
	if out, truncated := pickAddresses(short); truncated || len(out) != 2 || out[0] != "192.0.2.1" {
		t.Fatalf("short list: %v %v", out, truncated)
	}
}

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
