package protocol

import (
	"net"
	"net/netip"
	"net/url"
)

// Paths says from which kinds of address a machine can reach others, by
// its own addresses.
type Paths struct {
	Overlay, V4, V6 bool
}

// AllPaths assumes every kind, for a machine whose addresses are unknown.
var AllPaths = Paths{true, true, true}

// PathsFrom derives the kinds from a machine's addresses: an address in
// the overlay, an IPv4 address, an IPv6 address outside the overlay.
// Loopback and link-local addresses do not count.
func PathsFrom(addrs []netip.Addr, overlay []netip.Prefix) Paths {
	var p Paths
	for _, a := range addrs {
		a = a.Unmap()
		switch {
		case a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified():
		case InPrefixes(a, overlay):
			p.Overlay = true
		case a.Is4():
			p.V4 = true
		default:
			p.V6 = true
		}
	}
	return p
}

// LocalPaths are the Paths of this machine; AllPaths if its addresses
// cannot be read.
func LocalPaths(overlay []netip.Prefix) Paths {
	addrs, err := InterfaceAddrs()
	if err != nil {
		return AllPaths
	}
	return PathsFrom(addrs, overlay)
}

// InterfaceAddrs returns the addresses of this machine's interfaces.
func InterfaceAddrs() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(as))
	for _, a := range as {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip)
			}
		}
	}
	return out, nil
}

// Reaches reports whether an authority URL is worth trying with these
// paths: an address in the overlay needs the overlay, an IPv4 address
// IPv4, any other IPv6 address IPv6. Names and loopback addresses are
// always tried; a name may stand for any of them.
func (p Paths) Reaches(rawURL string, overlay []netip.Prefix) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	switch {
	case err != nil, ip.IsLoopback():
		return true
	case InPrefixes(ip, overlay):
		return p.Overlay
	case ip.Is4():
		return p.V4
	default:
		return p.V6
	}
}

// Order returns the indexes of the URLs worth trying with these paths,
// first first; all of them if none is.
func (p Paths) Order(urls []string, first int, overlay []netip.Prefix) []int {
	var out []int
	for i, u := range urls {
		if p.Reaches(u, overlay) {
			out = append(out, i)
		}
	}
	if len(out) == 0 {
		for i := range urls {
			out = append(out, i)
		}
	}
	for j, i := range out {
		if i == first && j > 0 {
			return append(append([]int{first}, out[:j]...), out[j+1:]...)
		}
	}
	return out
}
