package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// proposal is a check the machine suggests for its binding: as a line of
// the request, commented out if an administrator should decide. Without a
// check it is a note only.
type proposal struct {
	check  string // "TYPE TARGET"
	note   string
	active bool
}

// addrLifetime says whether an address stays or comes with a lease (DHCP,
// SLAAC); unknown where the system does not tell.
type addrLifetime int

const (
	addrUnknown addrLifetime = iota
	addrFixed
	addrLeased
)

// addrKey names an address on an interface.
type addrKey struct {
	index int
	addr  netip.Addr
}

// Request writes a binding request: the identity, the key to bind and the
// checks the machine can propose from where it stands. An administrator
// adjusts the checks and runs "ergosum bind" on it. With newKey the request
// names the next key, which is created unless one waits already; the daemon
// switches to it once the binding names it.
func (d *Daemon) Request(ctx context.Context, newKey bool, now time.Time) ([]byte, error) {
	key := d.Fingerprint()
	var head []string
	if newKey {
		next, err := d.NewKey()
		if err != nil {
			return nil, err
		}
		head = append(head, "# A new key: ergosumd switches to it once this binding is recorded,",
			"# and deletes the current key "+key+".")
		key = next
	}
	lines := append([]string{
		fmt.Sprintf("# Binding request for %s, written by ergosumd request at %s.", d.cfg.Identity, now.UTC().Format(time.RFC3339)),
		"# Keep the checks that hold for this machine and delete the others, then",
		`# hand the file to an ergosum administrator, who runs "ergosum bind FILE".`,
	}, head...)
	lines = append(lines, "identity "+d.cfg.Identity, "key "+key)
	for _, p := range d.propose(ctx) {
		lines = append(lines, "# "+p.note)
		switch {
		case p.check == "":
		case p.active:
			lines = append(lines, "check "+p.check)
		default:
			lines = append(lines, "# check "+p.check)
		}
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

// propose suggests checks: the tailnet name, and one check per address
// (see proposeAddresses). Configured addresses count as fixed; detected
// ones are fixed or leased as the system tells (Linux), or unknown.
func (d *Daemon) propose(ctx context.Context) []proposal {
	var out []proposal
	if name, err := d.tailnetName(ctx); err != nil {
		out = append(out, proposal{check: protocol.CheckTailnet + " NAME", note: "no tailnet name: " + err.Error()})
	} else {
		out = append(out, proposal{check: protocol.CheckTailnet + " " + name, note: "tailnet name (tailscale status)", active: true})
	}
	cands := d.detectAddresses()
	if len(d.cfg.Addresses) > 0 {
		return append(out, proposeAddresses(configured(d.cfg.Addresses, cands))...)
	}
	if lifetimes := addressLifetimes(); lifetimes != nil {
		fixed := false
		for i, c := range cands {
			a, _ := netip.ParseAddr(c.addr)
			cands[i].lifetime = lifetimes[addrKey{c.index, a}]
			fixed = fixed || cands[i].lifetime == addrFixed
		}
		if fixed {
			out = append(out, proposal{note: "Fixed addresses have no lifetime in the kernel. An older dhclient sets DHCP leases without one too: check that each is really fixed."})
		}
	}
	return append(out, proposeAddresses(cands)...)
}

// proposeAddresses suggests a check per address. A fixed address becomes
// an ip check, public or private: only the machine at that address can
// answer it, while a net check passes for a copy anywhere in the network. A
// leased address (DHCP, SLAAC) can change: in a private network it becomes
// a net check, a public one an ip check commented out. Of an address with
// unknown lifetime, a public one becomes an ip check and a private one a
// net check. IPv6 addresses and virtual interfaces are proposed commented
// out.
func proposeAddresses(cands []ifaceAddr) []proposal {
	var out []proposal
	orderAddresses(cands)
	seen := map[string]bool{}
	for _, c := range cands {
		a, err := netip.ParseAddr(c.addr)
		if err != nil {
			continue
		}
		p := proposal{active: a.Is4() && !virtualInterface(c.iface)}
		where := c.iface
		if where == "" {
			where = "configured"
		}
		switch {
		case c.lifetime == addrFixed && a.IsPrivate():
			p.check = protocol.CheckIP + " " + c.addr
			p.note = where + ": fixed private address; checked by an authority attached to its network"
		case c.lifetime == addrFixed:
			p.check = protocol.CheckIP + " " + c.addr
			p.note = where + ": fixed public address"
		case a.IsPrivate() && c.prefix.IsValid():
			p.check = protocol.CheckNet + " " + c.prefix.String()
			p.note = fmt.Sprintf("%s: private network %s; checked by an authority attached to it", where, netip.PrefixFrom(a, c.prefix.Bits()))
			if c.lifetime == addrLeased {
				p.note = fmt.Sprintf("%s: DHCP lease in private network %s; checked by an authority attached to it", where, netip.PrefixFrom(a, c.prefix.Bits()))
			}
		case a.IsPrivate():
			p.check = protocol.CheckNet + " " + c.addr + "/??"
			p.note = where + ": private address of an unknown network; name the network"
			p.active = false
		case c.lifetime == addrLeased:
			p.check = protocol.CheckIP + " " + c.addr
			p.note = where + ": public address from DHCP or SLAAC; bind it only if it does not change"
			p.active = false
		default:
			p.check = protocol.CheckIP + " " + c.addr
			p.note = where + ": public address"
		}
		switch {
		case !a.Is6():
		case c.lifetime == addrUnknown:
			p.note += "; IPv6, bind it only if the address is fixed"
		case c.lifetime == addrFixed:
			p.note += "; IPv6, bind it if the authorities reach the machine over IPv6"
		default:
			p.note += "; IPv6"
		}
		if virtualInterface(c.iface) {
			p.note += "; virtual interface"
		}
		if seen[p.check] {
			continue
		}
		seen[p.check] = true
		out = append(out, p)
	}
	return out
}

// configured keeps the configured addresses, with the interface they were
// found on if any. They count as fixed.
func configured(addrs []string, detected []ifaceAddr) []ifaceAddr {
	out := make([]ifaceAddr, 0, len(addrs))
	for _, s := range addrs {
		c := ifaceAddr{addr: s}
		for _, dc := range detected {
			if dc.addr == s {
				c = dc
				break
			}
		}
		c.lifetime = addrFixed
		out = append(out, c)
	}
	return out
}

// tailscaleCLIs are where the Tailscale client is when it is not in PATH,
// by GOOS. On macOS launchd starts the daemon with
// PATH=/usr/bin:/bin:/usr/sbin:/sbin; the client is the CLI in the app
// (App Store and standalone versions) or Homebrew's (Intel, Apple Silicon).
var tailscaleCLIs = map[string][]string{
	"darwin": {
		"/Applications/Tailscale.app/Contents/MacOS/Tailscale",
		"/usr/local/bin/tailscale",
		"/opt/homebrew/bin/tailscale",
	},
}

// tailscaleCLI returns the Tailscale client to run: tailscale in PATH,
// else the first of tailscaleCLIs[goos] that exists.
func tailscaleCLI(goos string) string {
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p
	}
	for _, p := range tailscaleCLIs[goos] {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return "tailscale"
}

// tailnetName asks the Tailscale client for the machine's name.
func tailnetName(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, tailscaleCLI(runtime.GOOS), "status", "--json", "--peers=false").Output() //nolint:gosec // a fixed list of places
	if err != nil {
		return "", fmt.Errorf("tailscale status: %w", err)
	}
	var st struct {
		Self struct{ DNSName string }
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return "", fmt.Errorf("tailscale status: %w", err)
	}
	name := strings.ToLower(strings.TrimSuffix(st.Self.DNSName, "."))
	if !protocol.ValidDNSName(name) {
		return "", fmt.Errorf("tailscale status names no DNS name (%q)", st.Self.DNSName)
	}
	return name, nil
}
