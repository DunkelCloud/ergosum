package authority

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// Route says how a callback leaves the authority: the check kind, and an
// optional source address and interface to bind to.
type Route struct {
	Check     string
	Source    netip.Addr
	Interface string
}

// Network dials callback targets. The production implementation is
// SystemNetwork; tests substitute a simulated network.
type Network interface {
	Dial(ctx context.Context, route Route, address string) (net.Conn, error)
}

// DefaultTailnetPrefixes are the address ranges Tailscale assigns.
var DefaultTailnetPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// SystemNetwork dials with the operating system and enforces the
// reachability rules: a tailnet callback must reach an overlay address, an
// ip or net callback must neither reach nor leave from one. That keeps an
// underlay check from silently traveling over the overlay or an exit node.
type SystemNetwork struct {
	TailnetPrefixes []netip.Prefix
	Resolver        *net.Resolver
	Timeout         time.Duration
}

// ErrRouteViolation is returned when a connection would break the
// reachability rules.
var ErrRouteViolation = errors.New("callback route violates reachability rules")

func (n *SystemNetwork) inTailnet(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range n.TailnetPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// CheckRemote applies the reachability rule to a resolved remote address.
func (n *SystemNetwork) CheckRemote(check string, remote netip.Addr) error {
	overlay := n.inTailnet(remote)
	if check == protocol.CheckTailnet && !overlay {
		return fmt.Errorf("%w: tailnet callback to non-overlay address %s", ErrRouteViolation, remote)
	}
	if check != protocol.CheckTailnet && overlay {
		return fmt.Errorf("%w: %s callback to overlay address %s", ErrRouteViolation, check, remote)
	}
	return nil
}

// CheckLocal applies the reachability rule to the local end of a connection.
func (n *SystemNetwork) CheckLocal(check string, local netip.Addr) error {
	if check != protocol.CheckTailnet && n.inTailnet(local) {
		return fmt.Errorf("%w: %s callback leaves from overlay address %s", ErrRouteViolation, check, local)
	}
	return nil
}

// Dial resolves address, checks the rules and connects from the route's
// source address and interface.
func (n *SystemNetwork) Dial(ctx context.Context, route Route, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		r := n.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		addrs, err = r.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	var lastErr error
	for _, a := range addrs {
		if err := n.CheckRemote(route.Check, a); err != nil {
			lastErr = err
			continue
		}
		d := net.Dialer{Timeout: n.Timeout, Control: bindToDevice(route.Interface)}
		if route.Source.IsValid() {
			d.LocalAddr = &net.TCPAddr{IP: route.Source.AsSlice()}
		}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
		if err != nil {
			lastErr = err
			continue
		}
		if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			if local, ok := netip.AddrFromSlice(la.IP); ok {
				if err := n.CheckLocal(route.Check, local); err != nil {
					_ = conn.Close()
					lastErr = err
					continue
				}
			}
		}
		return conn, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no address for %s", host)
	}
	return nil, lastErr
}
