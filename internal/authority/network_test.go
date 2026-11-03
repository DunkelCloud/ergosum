package authority

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

func TestReachabilityRules(t *testing.T) {
	n := &SystemNetwork{TailnetPrefixes: protocol.DefaultOverlayPrefixes}
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

// TestIPCheckRoutes: an ip check inside an attached network leaves by that
// network's route, any other public address by the ip route, and a private
// address outside all attached networks makes the instance not responsible.
func TestIPCheckRoutes(t *testing.T) {
	cfg := Config{}
	cfg.Callbacks.IP = RouteConfig{Source: "203.0.113.2", Interface: "eth0"}
	cfg.Callbacks.Networks = []NetworkRoute{
		{CIDR: "10.99.0.0/24", RouteConfig: RouteConfig{Source: "10.99.0.2", Interface: "eth1"}},
		{CIDR: "fd00:99::/64", RouteConfig: RouteConfig{Interface: "eth1"}},
		{CIDR: "198.51.100.0/24", RouteConfig: RouteConfig{Source: "198.51.100.2", Interface: "eth2"}},
	}
	cfg.SetDefaults()
	rs, err := cfg.routes()
	if err != nil {
		t.Fatal(err)
	}
	a := &Authority{cfg: cfg, routes: rs}
	public := Route{Check: protocol.CheckIP, Source: netip.MustParseAddr("203.0.113.2"), Interface: "eth0"}
	lan := Route{Check: protocol.CheckIP, Source: netip.MustParseAddr("10.99.0.2"), Interface: "eth1"}
	for _, c := range []struct {
		target string
		route  Route
		port   int
	}{
		{"192.0.2.10", public, 7433},
		{"2001:db8::10", public, 7433},
		{"10.99.0.20", lan, 7433},
		{"10.99.0.20:7500", lan, 7500},
		{"[fd00:99::20]:7500", Route{Check: protocol.CheckIP, Interface: "eth1"}, 7500},
		// A public network in the list takes its route as well.
		{"198.51.100.20", Route{Check: protocol.CheckIP, Source: netip.MustParseAddr("198.51.100.2"), Interface: "eth2"}, 7433},
	} {
		b := &journal.Binding{Checks: []journal.Check{{Type: protocol.CheckIP, Target: c.target}}}
		plan, nr := a.plan(b, nil)
		if nr != "" || len(plan) != 1 {
			t.Errorf("%s: plan %+v, not responsible %q", c.target, plan, nr)
			continue
		}
		if plan[0].route != c.route || plan[0].port != c.port {
			t.Errorf("%s: route %+v port %d, want %+v port %d", c.target, plan[0].route, plan[0].port, c.route, c.port)
		}
	}
	for _, target := range []string{"10.98.0.20", "172.16.0.5:7500", "fd00:98::20"} {
		b := &journal.Binding{Checks: []journal.Check{
			{Type: protocol.CheckIP, Target: "192.0.2.10"},
			{Type: protocol.CheckIP, Target: target},
		}}
		if plan, nr := a.plan(b, nil); nr != "ip "+target || plan != nil {
			t.Errorf("%s: plan %+v, not responsible %q", target, plan, nr)
		}
	}
}
