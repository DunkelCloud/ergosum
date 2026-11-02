package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ergosum/internal/jwt"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/metrics"
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
	// A Mac: Wi-Fi after VPN tunnels and the bridge of Internet Sharing.
	mac := []ifaceAddr{
		{addr: "10.8.0.2", iface: "utun4", index: 20},
		{addr: "192.168.2.1", iface: "bridge100", index: 21},
		{addr: "192.0.2.30", iface: "en0", index: 22},
	}
	if out, _ := pickAddresses(mac); out[0] != "192.0.2.30" {
		t.Fatalf("en0 not first: %v", out)
	}
}

// Interfaces of tunnels, bridges and virtual machines count as virtual, on
// Linux and on macOS; Ethernet and Wi-Fi do not.
func TestVirtualInterface(t *testing.T) {
	for name, want := range map[string]bool{
		"eth0": false, "enp3s0": false, "wlan0": false, "en0": false, "en7": false,
		"docker0": true, "br-1a2b": true, "tailscale0": true, "wg0": true, "tun0": true,
		"utun3": true, "bridge0": true, "bridge100": true, "awdl0": true, "llw0": true,
		"vmnet8": true, "vboxnet0": true, "feth1": true,
	} {
		if got := virtualInterface(name); got != want {
			t.Errorf("virtualInterface(%q) = %v, want %v", name, got, want)
		}
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

// A long round yields no clock skew estimate: the answer may come from any
// point in it.
func TestObserveSkew(t *testing.T) {
	d := &Daemon{metrics: metrics.NewRegistry()}
	d.mClockSkew = d.metrics.Gauge("skew", "")
	sent := time.Unix(1_800_000_000, 0)
	d.observeSkew(sent.Add(3*time.Second), sent, sent.Add(2*time.Second))
	if got := d.mClockSkew.Get(""); got != 2 {
		t.Fatalf("short round: %v", got)
	}
	d.observeSkew(sent.Add(60*time.Second), sent, sent.Add(80*time.Second))
	if got := d.mClockSkew.Get(""); got != 2 {
		t.Fatalf("a long round changed the estimate: %v", got)
	}
}

// The Tailscale client is the one in PATH, else the first that exists of
// the places known for the system (on macOS: in the app, Homebrew's).
func TestTailscaleCLI(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", filepath.Join(dir, "bin"))
	missing, present := filepath.Join(dir, "missing"), filepath.Join(dir, "Tailscale")
	if err := os.WriteFile(present, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // a test executable
		t.Fatal(err)
	}
	tailscaleCLIs["testos"] = []string{missing, dir, present}
	t.Cleanup(func() { delete(tailscaleCLIs, "testos") })
	if got := tailscaleCLI("testos"); got != present {
		t.Fatalf("got %s, want %s", got, present)
	}
	if got := tailscaleCLI("otheros"); got != "tailscale" {
		t.Fatalf("no client anywhere: got %s", got)
	}
	name := "tailscale"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	inPath := filepath.Join(dir, "bin", name)
	if err := os.MkdirAll(filepath.Dir(inPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inPath, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // a test executable
		t.Fatal(err)
	}
	if got := tailscaleCLI("testos"); got != inPath {
		t.Fatalf("PATH not first: got %s, want %s", got, inPath)
	}
}

// A request proposes the tailnet name and checks for the addresses:
// public IPv4 active, IPv6 and unknown networks commented out.
func TestRequest(t *testing.T) {
	cfg := Config{
		Identity: "host1.example.com", StateDir: t.TempDir(), TokenGroup: "-",
		Addresses:   []string{"198.51.100.20", "2001:db8::20", "10.99.0.7"},
		Authorities: []AuthorityConfig{{URL: "https://192.0.2.1:7432", Key: "SHA256:" + strings.Repeat("A", 43)}},
	}
	d, err := New(cfg, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		TailnetName: func(context.Context) (string, error) { return "host1.tailnet.example.com", nil }})
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Request(context.Background(), false, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"\nidentity host1.example.com\n",
		"\nkey " + d.Fingerprint() + "\n",
		"\ncheck tailnet host1.tailnet.example.com\n",
		"\ncheck ip 198.51.100.20\n",
		"\n# check ip 2001:db8::20\n",
		"\n# check net 10.99.0.7/??\n",
	} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("request lacks %q:\n%s", want, out)
		}
	}
	// A request for a new key keeps the current one in use.
	cur := d.Fingerprint()
	out, err = d.Request(context.Background(), true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	next := d.PendingFingerprint()
	if next == "" || next == cur || d.Fingerprint() != cur || !strings.Contains(string(out), "key "+next) {
		t.Fatalf("new key %q, current %q:\n%s", next, d.Fingerprint(), out)
	}
	// Asked again, it names the same next key.
	if _, err := d.Request(context.Background(), true, time.Now()); err != nil || d.PendingFingerprint() != next {
		t.Fatalf("second request: %v %s", err, d.PendingFingerprint())
	}
}

func TestInflight(t *testing.T) {
	const a, b = "SHA256:authority-a", "SHA256:authority-b"
	now := time.Unix(1_800_000_000, 0)
	f := newInflight(func() time.Time { return now })
	id := "AAAAAAAAAAAAAAAAAAAAAA"
	if got := f.status(id, a); got != protocol.StatusNoOpenRequest {
		t.Fatalf("unknown request: %s", got)
	}
	f.add(id, a)
	if got := f.status(id, a); got != protocol.StatusConfirmed {
		t.Fatalf("request in flight: %s", got)
	}
	// The same request ID from another instance is not ours.
	if got := f.status(id, b); got != protocol.StatusNoOpenRequest {
		t.Fatalf("request to another instance: %s", got)
	}
	// Given up: a late callback from the same instance hears "ended", any
	// other instance still "no open request".
	f.remove(id)
	if got := f.status(id, a); got != protocol.StatusEnded {
		t.Fatalf("ended request: %s", got)
	}
	if got := f.status(id, b); got != protocol.StatusNoOpenRequest {
		t.Fatalf("ended request, other instance: %s", got)
	}
	now = now.Add(protocol.EndedTTL + time.Second)
	if got := f.status(id, a); got != protocol.StatusNoOpenRequest {
		t.Fatalf("long ended request: %s", got)
	}
}

// A key switch keeps the old key until a token is issued for the new one.
// A refusal by every authority goes back to the old key and keeps the new
// one waiting; an outage changes nothing.
func TestKeySwitchSettles(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Identity: "host1.example.com", StateDir: dir, TokenGroup: "-",
		Authorities: []AuthorityConfig{{URL: "https://192.0.2.1:7432", Key: "SHA256:" + strings.Repeat("A", 43)}},
	}
	d, err := New(cfg, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	old := d.Fingerprint()
	next, err := d.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	onDisk := func(name string) string {
		k, err := keys.Load(filepath.Join(dir, name))
		if err != nil {
			return ""
		}
		return keys.Fingerprint(&k.PublicKey)
	}
	refused := errors.Join(fmt.Errorf("a: %w", &RequestError{Status: 403, Code: "denied"}), fmt.Errorf("b: %w", &RequestError{Status: 403, Code: "denied"}))
	outage := errors.Join(fmt.Errorf("a: %w", &RequestError{Status: 403}), errors.New("b: connection refused"))

	if err := d.switchToPending(d.pending); err != nil {
		t.Fatal(err)
	}
	if d.Fingerprint() != next || onDisk("identity.key") != next || onDisk("identity.key.old") != old || onDisk("identity.key.new") != "" {
		t.Fatal("switch: current, old and next key not where expected")
	}
	d.settleKeySwitch(outage)
	if d.Fingerprint() != next || onDisk("identity.key.old") != old {
		t.Fatal("an outage changed the keys")
	}
	d.settleKeySwitch(refused)
	if d.Fingerprint() != old || d.PendingFingerprint() != next || onDisk("identity.key") != old ||
		onDisk("identity.key.new") != next || onDisk("identity.key.old") != "" {
		t.Fatal("refused: not back on the old key with the new one waiting")
	}
	if !d.now().Before(d.holdPending) {
		t.Fatal("no pause before the next switch")
	}
	if err := d.switchToPending(d.pending); err != nil {
		t.Fatal(err)
	}
	d.settleKeySwitch(nil)
	if d.Fingerprint() != next || onDisk("identity.key") != next || onDisk("identity.key.old") != "" {
		t.Fatal("token for the new key: old key not deleted")
	}
}
