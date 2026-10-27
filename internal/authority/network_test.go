package authority

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/DunkelCloud/ergosum/internal/protocol"
)

func TestReachabilityRules(t *testing.T) {
	n := &SystemNetwork{TailnetPrefixes: DefaultTailnetPrefixes}
	overlay := netip.MustParseAddr("100.101.102.103")
	overlay6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	underlay := netip.MustParseAddr("192.0.2.10")

	ok := []struct {
		check string
		addr  netip.Addr
	}{
		{protocol.CheckTailnet, overlay},
		{protocol.CheckTailnet, overlay6},
		{protocol.CheckIP, underlay},
		{protocol.CheckNet, netip.MustParseAddr("198.51.100.20")},
	}
	for _, c := range ok {
		if err := n.CheckRemote(c.check, c.addr); err != nil {
			t.Errorf("%s to %s: %v", c.check, c.addr, err)
		}
	}
	bad := []struct {
		check string
		addr  netip.Addr
	}{
		{protocol.CheckTailnet, underlay},
		{protocol.CheckIP, overlay},
		{protocol.CheckNet, overlay6},
		{protocol.CheckIP, netip.MustParseAddr("::ffff:100.64.1.1")},
	}
	for _, c := range bad {
		if err := n.CheckRemote(c.check, c.addr); !errors.Is(err, ErrRouteViolation) {
			t.Errorf("%s to %s allowed", c.check, c.addr)
		}
	}
	// An underlay callback must not leave from an overlay address, as it
	// would through an exit node.
	if err := n.CheckLocal(protocol.CheckIP, overlay); !errors.Is(err, ErrRouteViolation) {
		t.Error("ip callback from an overlay address allowed")
	}
	if err := n.CheckLocal(protocol.CheckIP, netip.MustParseAddr("203.0.113.2")); err != nil {
		t.Error(err)
	}
}

func TestAttachedNetworks(t *testing.T) {
	cfg := Config{}
	cfg.Callbacks.Networks = []NetworkRoute{{CIDR: "198.51.100.0/24"}, {CIDR: "2001:db8:1::/48"}}
	rs, err := cfg.routes()
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{
		"198.51.100.0/24":   true,
		"198.51.100.64/26":  true,
		"198.51.0.0/16":     false, // wider than the attached network
		"192.0.2.0/24":      false,
		"2001:db8:1:2::/64": true,
	} {
		if _, got := rs.network(netip.MustParsePrefix(p)); got != want {
			t.Errorf("%s: attached=%v, want %v", p, got, want)
		}
	}
}
