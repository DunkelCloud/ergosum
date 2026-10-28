package authority

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/DunkelCloud/ergosum/internal/journal"
	"github.com/DunkelCloud/ergosum/internal/keys"
	"github.com/DunkelCloud/ergosum/internal/protocol"
)

// Config is the authority configuration (serve.yaml).
type Config struct {
	// Instance names this instance as the origin of its journal events.
	Instance string `yaml:"instance"`
	// TrustDomain is the SPIFFE trust domain, e.g. example.com.
	TrustDomain string `yaml:"trust_domain"`
	// Issuer is the "iss" claim, shared by all instances.
	Issuer string `yaml:"issuer"`
	// Audience is the only "aud" value. Default: vault.
	Audience string `yaml:"audience"`
	// TokenTTL is the token lifetime. Default: 30m.
	TokenTTL time.Duration `yaml:"token_ttl"`
	// ClockSkew is the accepted deviation of request timestamps. Default: 2m.
	ClockSkew time.Duration `yaml:"clock_skew"`
	// SigningKey is the PEM file with the instance key, optionally
	// passphrase-encrypted (then the instance starts sealed).
	SigningKey string `yaml:"signing_key"`
	// Journal is the SQLite file. Default: /var/lib/ergosum/journal.db.
	Journal string `yaml:"journal"`
	// Listen is the TLS listener for token requests and binding writes,
	// normally the instance's overlay address with port 7432. It is
	// required and must name an address.
	Listen string `yaml:"listen"`
	// ListenAllInterfaces allows Listen and Replication.Listen to bind all
	// interfaces (":7432", "0.0.0.0:7432", "[::]:7432").
	ListenAllInterfaces bool `yaml:"listen_all_interfaces"`
	// OpsListen serves /metrics, /healthz and the public keys over plain
	// HTTP. Default: 127.0.0.1:7434. Empty string "-" disables it.
	OpsListen string `yaml:"ops_listen"`
	// ControlSocket is the local Unix socket for "ergosum unseal" and
	// "ergosum journal". It lives in the state directory, so that it needs
	// no runtime directory of its own. Default:
	// /var/lib/ergosum/control.sock.
	ControlSocket string `yaml:"control_socket"`
	// Callbacks configures how callbacks leave this instance.
	Callbacks CallbackConfig `yaml:"callbacks"`
	// Registry is the admin public key registry (trust root).
	Registry journal.RegistryConfig `yaml:"registry"`
	// Replication configures the peers this instance replicates its
	// journal with.
	Replication ReplicationConfig `yaml:"replication"`
	// Compaction configures checkpoints and the shortening of the journal.
	Compaction CompactionConfig `yaml:"compaction"`
}

// ReplicationConfig lists the other instances (ADR 0003, Replication).
type ReplicationConfig struct {
	// Listen is the mutual-TLS listener for peers, normally the
	// instance's overlay address with port 7435. Required when a peer has
	// a URL. Binding all interfaces needs listen_all_interfaces.
	Listen string `yaml:"listen"`
	// Peers are all other instances of the trust domain.
	Peers []PeerConfig `yaml:"peers"`
}

// PeerConfig is another instance.
type PeerConfig struct {
	// Name is the peer's instance name, the origin of its events.
	Name string `yaml:"name"`
	// URL of the peer's replication listener, e.g.
	// https://100.64.0.11:7435. A peer without URL is known, so that its
	// events are accepted when another peer forwards them, but it gets no
	// pushes and compaction does not wait for it.
	URL string `yaml:"url"`
	// Key is the peer's public instance key (PEM), as printed by
	// "ergosum keygen". It pins the peer's TLS key and verifies its
	// observations and checkpoints.
	Key string `yaml:"key"`
	// Fingerprint, if set, must match Key.
	Fingerprint string `yaml:"fingerprint"`
}

// CompactionConfig configures checkpoints and compaction.
type CompactionConfig struct {
	// CheckpointInterval is how often the instance writes a checkpoint.
	// Default: 24h.
	CheckpointInterval time.Duration `yaml:"checkpoint_interval"`
	// Interval is how often the instance checks whether a checkpoint is
	// due and compacts. Default: 1h.
	Interval  time.Duration   `yaml:"interval"`
	Retention RetentionConfig `yaml:"retention"`
	// Archive is a directory to which events are exported before they are
	// deleted. Empty: no archive.
	Archive string `yaml:"archive"`
}

// RetentionConfig is how long events stay once a checkpoint covers them.
// Zero keeps them.
type RetentionConfig struct {
	// Observations except key_duplicate. Default: 2160h (90 days).
	Observations *time.Duration `yaml:"observations"`
	// KeyDuplicate observations, the evidence of a copied key. Default:
	// kept.
	KeyDuplicate time.Duration `yaml:"key_duplicate"`
	// Bindings: binding events. Default: kept. The winner of every
	// identity lives on in the checkpoint either way.
	Bindings time.Duration `yaml:"bindings"`
}

func (r RetentionConfig) retention() journal.Retention {
	ret := journal.Retention{KeyDuplicate: r.KeyDuplicate, Bindings: r.Bindings}
	if r.Observations != nil {
		ret.Observations = *r.Observations
	}
	return ret
}

// peer is a validated PeerConfig.
type peer struct {
	name        string
	url         string
	key         *ecdsa.PublicKey
	fingerprint string
}

func (c *Config) peers() ([]peer, error) {
	var out []peer
	seen := map[string]bool{}
	for i, pc := range c.Replication.Peers {
		if !validInstanceName(pc.Name) || pc.Name == c.Instance {
			return nil, fmt.Errorf("replication.peers[%d]: bad name %q", i, pc.Name)
		}
		if seen[pc.Name] {
			return nil, fmt.Errorf("replication.peers: %q listed twice", pc.Name)
		}
		seen[pc.Name] = true
		key, err := keys.ParsePublicPEM([]byte(pc.Key))
		if err != nil {
			return nil, fmt.Errorf("replication.peers %q: key: %w", pc.Name, err)
		}
		fp := keys.Fingerprint(key)
		if pc.Fingerprint != "" && pc.Fingerprint != fp {
			return nil, fmt.Errorf("replication.peers %q: fingerprint %s does not match the key (%s)", pc.Name, pc.Fingerprint, fp)
		}
		if pc.URL != "" {
			u, err := url.Parse(pc.URL)
			if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
				return nil, fmt.Errorf("replication.peers %q: url %q must be https://host:port", pc.Name, pc.URL)
			}
		}
		out = append(out, peer{name: pc.Name, url: strings.TrimSuffix(pc.URL, "/"), key: key, fingerprint: fp})
	}
	return out, nil
}

// validInstanceName allows names such as authority-a or site-a.example.com.
func validInstanceName(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

// CallbackConfig configures the callback client.
type CallbackConfig struct {
	// Port is the daemon callback port when a target names none. Default: 7433.
	Port int `yaml:"port"`
	// Timeout per callback. Default: 5s.
	Timeout time.Duration `yaml:"timeout"`
	// Tailnet routes tailnet callbacks.
	Tailnet TailnetRoute `yaml:"tailnet"`
	// IP routes ip callbacks; they must use the public underlay.
	IP RouteConfig `yaml:"ip"`
	// Networks lists the networks attached directly to this instance; net
	// checks are performed only for prefixes inside one of them.
	Networks []NetworkRoute `yaml:"networks"`
}

// RouteConfig is a source address and interface for outgoing callbacks.
type RouteConfig struct {
	Source    string `yaml:"source"`
	Interface string `yaml:"interface"`
}

// TailnetRoute adds the overlay address ranges to RouteConfig.
type TailnetRoute struct {
	RouteConfig `yaml:",inline"`
	// Prefixes of the overlay. Default: 100.64.0.0/10, fd7a:115c:a1e0::/48.
	Prefixes []string `yaml:"prefixes"`
}

// NetworkRoute is a directly attached network.
type NetworkRoute struct {
	CIDR        string `yaml:"cidr"`
	RouteConfig `yaml:",inline"`
}

// LoadConfig reads and validates a YAML configuration file.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return Config{}, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	c.SetDefaults()
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// SetDefaults fills unset fields.
func (c *Config) SetDefaults() {
	if c.Audience == "" {
		c.Audience = "vault"
	}
	if c.TokenTTL == 0 {
		c.TokenTTL = 30 * time.Minute
	}
	if c.ClockSkew == 0 {
		c.ClockSkew = 2 * time.Minute
	}
	if c.Journal == "" {
		c.Journal = "/var/lib/ergosum/journal.db"
	}
	if c.OpsListen == "" {
		c.OpsListen = fmt.Sprintf("127.0.0.1:%d", protocol.DefaultOpsPort)
	}
	if c.ControlSocket == "" {
		c.ControlSocket = "/var/lib/ergosum/control.sock"
	}
	if c.Compaction.CheckpointInterval == 0 {
		c.Compaction.CheckpointInterval = 24 * time.Hour
	}
	if c.Compaction.Interval == 0 {
		c.Compaction.Interval = time.Hour
	}
	if c.Compaction.Retention.Observations == nil {
		d := 90 * 24 * time.Hour
		c.Compaction.Retention.Observations = &d
	}
	if c.Callbacks.Port == 0 {
		c.Callbacks.Port = protocol.DefaultCallbackPort
	}
	if c.Callbacks.Timeout == 0 {
		c.Callbacks.Timeout = 5 * time.Second
	}
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	var errs []error
	if !validInstanceName(c.Instance) {
		errs = append(errs, fmt.Errorf("instance %q: use lower-case letters, digits, hyphens and dots", c.Instance))
	}
	if !protocol.ValidDNSName(c.TrustDomain) {
		errs = append(errs, fmt.Errorf("trust_domain %q is not a DNS name", c.TrustDomain))
	}
	if c.Issuer == "" {
		errs = append(errs, errors.New("issuer is required"))
	}
	if c.SigningKey == "" {
		errs = append(errs, errors.New("signing_key is required"))
	}
	if c.TokenTTL < 10*time.Second || c.TokenTTL > 24*time.Hour {
		errs = append(errs, fmt.Errorf("token_ttl %s out of range", c.TokenTTL))
	}
	if c.ClockSkew < time.Second || c.ClockSkew > time.Hour {
		errs = append(errs, fmt.Errorf("clock_skew %s out of range (1s to 1h)", c.ClockSkew))
	}
	if c.Callbacks.Port < 1 || c.Callbacks.Port > 65535 {
		errs = append(errs, fmt.Errorf("callbacks.port %d out of range", c.Callbacks.Port))
	}
	if c.Callbacks.Timeout < 100*time.Millisecond || c.Callbacks.Timeout > time.Minute {
		errs = append(errs, fmt.Errorf("callbacks.timeout %s out of range (100ms to 1m)", c.Callbacks.Timeout))
	}
	if err := c.validateListen("listen", c.Listen, protocol.DefaultAuthorityPort); err != nil {
		errs = append(errs, err)
	}
	if ps, err := c.peers(); err != nil {
		errs = append(errs, err)
	} else {
		pushes := false
		for _, p := range ps {
			pushes = pushes || p.url != ""
		}
		switch {
		case c.Replication.Listen != "":
			if err := c.validateListen("replication.listen", c.Replication.Listen, protocol.DefaultReplicationPort); err != nil {
				errs = append(errs, err)
			}
		case pushes:
			errs = append(errs, errors.New("replication.listen is required when a peer has a url"))
		}
	}
	if c.Compaction.CheckpointInterval < time.Minute || c.Compaction.Interval < time.Second {
		errs = append(errs, errors.New("compaction: checkpoint_interval must be at least 1m and interval at least 1s"))
	}
	if r := c.Compaction.Retention; (r.Observations != nil && *r.Observations < 0) || r.KeyDuplicate < 0 || r.Bindings < 0 {
		errs = append(errs, errors.New("compaction.retention: durations must not be negative"))
	}
	if _, err := c.routes(); err != nil {
		errs = append(errs, err)
	}
	if _, err := journal.NewRegistry(c.Registry); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// validateListen requires an address to bind: the API and the replication
// listener belong on the overlay, and binding all interfaces would expose
// them on a public host.
func (c *Config) validateListen(field, addr string, port int) error {
	if addr == "" {
		return fmt.Errorf("%s is required, normally the instance's overlay address and port %d", field, port)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s %q: %w", field, addr, err)
	}
	if c.ListenAllInterfaces {
		return nil
	}
	if a, err := netip.ParseAddr(host); host == "" || (err == nil && a.IsUnspecified()) {
		return fmt.Errorf("%s %q binds all interfaces; name an address or set listen_all_interfaces", field, addr)
	}
	return nil
}

type routes struct {
	tailnet  Route
	ip       Route
	networks []attachedNetwork
	overlay  []netip.Prefix
}

type attachedNetwork struct {
	prefix netip.Prefix
	route  Route
}

func parseRoute(check string, rc RouteConfig) (Route, error) {
	r := Route{Check: check, Interface: rc.Interface}
	if rc.Source != "" {
		a, err := netip.ParseAddr(rc.Source)
		if err != nil {
			return r, fmt.Errorf("callbacks: bad source %q", rc.Source)
		}
		r.Source = a
	}
	return r, nil
}

func (c *Config) routes() (routes, error) {
	var rs routes
	var err error
	if rs.tailnet, err = parseRoute(protocol.CheckTailnet, c.Callbacks.Tailnet.RouteConfig); err != nil {
		return rs, err
	}
	if rs.ip, err = parseRoute(protocol.CheckIP, c.Callbacks.IP); err != nil {
		return rs, err
	}
	for _, n := range c.Callbacks.Networks {
		p, err := netip.ParsePrefix(n.CIDR)
		if err != nil || p.Masked() != p {
			return rs, fmt.Errorf("callbacks: bad network %q", n.CIDR)
		}
		r, err := parseRoute(protocol.CheckNet, n.RouteConfig)
		if err != nil {
			return rs, err
		}
		rs.networks = append(rs.networks, attachedNetwork{prefix: p, route: r})
	}
	if rs.overlay, err = protocol.ParsePrefixes(c.Callbacks.Tailnet.Prefixes); err != nil {
		return rs, fmt.Errorf("callbacks: tailnet: %w", err)
	}
	return rs, nil
}

// network returns the attached network that contains prefix p entirely.
func (rs routes) network(p netip.Prefix) (attachedNetwork, bool) {
	for _, n := range rs.networks {
		if n.prefix.Bits() <= p.Bits() && n.prefix.Contains(p.Addr()) {
			return n, true
		}
	}
	return attachedNetwork{}, false
}
