package authority

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/DunkelCloud/ergosum/internal/journal"
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
	// Listen is the TLS listener for token requests and binding writes.
	// Default: :7432.
	Listen string `yaml:"listen"`
	// OpsListen serves /metrics, /healthz and the public keys over plain
	// HTTP. Default: 127.0.0.1:7434. Empty string "-" disables it.
	OpsListen string `yaml:"ops_listen"`
	// UnsealSocket is the local Unix socket for "ergosum unseal". It lives
	// in the state directory, so that it needs no runtime directory of its
	// own. Default: /var/lib/ergosum/unseal.sock.
	UnsealSocket string `yaml:"unseal_socket"`
	// Callbacks configures how callbacks leave this instance.
	Callbacks CallbackConfig `yaml:"callbacks"`
	// Registry is the admin public key registry (trust root).
	Registry journal.RegistryConfig `yaml:"registry"`
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
	if c.Listen == "" {
		c.Listen = fmt.Sprintf(":%d", protocol.DefaultAuthorityPort)
	}
	if c.OpsListen == "" {
		c.OpsListen = fmt.Sprintf("127.0.0.1:%d", protocol.DefaultOpsPort)
	}
	if c.UnsealSocket == "" {
		c.UnsealSocket = "/var/lib/ergosum/unseal.sock"
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
	if c.Instance == "" {
		errs = append(errs, errors.New("instance is required"))
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
	if _, err := c.routes(); err != nil {
		errs = append(errs, err)
	}
	if _, err := journal.NewRegistry(c.Registry); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
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
	if len(c.Callbacks.Tailnet.Prefixes) == 0 {
		rs.overlay = DefaultTailnetPrefixes
	} else {
		for _, s := range c.Callbacks.Tailnet.Prefixes {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return rs, fmt.Errorf("callbacks: bad tailnet prefix %q", s)
			}
			rs.overlay = append(rs.overlay, p.Masked())
		}
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
