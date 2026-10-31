package protocol

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

const fpA = "SHA256:" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestValidAuthorityURL(t *testing.T) {
	for _, ok := range []string{
		"https://100.64.0.10:7432",
		"https://[fd7a:115c:a1e0::a]:7432",
		"https://[2001:db8::10]:7432",
		"https://lii-0.ergosum.example.com:7432",
		"https://127.0.0.1:1",
	} {
		if err := ValidAuthorityURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://100.64.0.10:7432",
		"https://100.64.0.10",
		"https://100.64.0.10:0",
		"https://100.64.0.10:65536",
		"https://100.64.0.10:07432",
		"https://100.64.0.10:7432/",
		"https://100.64.0.10:7432/v1",
		"https://100.64.0.10:7432?x=1",
		"https://100.64.0.10:7432#x",
		"https://user@100.64.0.10:7432",
		"https://[fe80::1%25eth0]:7432",
		"https://[::ffff:192.0.2.1]:7432",
		"https://localhost:7432",
		"https://Upper.example.com:7432",
		"https://1.2.3:7432",
	} {
		if err := ValidAuthorityURL(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestAuthorityListValidate(t *testing.T) {
	good := func() AuthorityList {
		return AuthorityList{V: Version, TrustDomain: "example.com", Serial: 1, Authorities: []ListedAuthority{
			{Key: fpA, URLs: []string{"https://100.64.0.10:7432", "https://192.0.2.10:7432"}},
		}}
	}
	l := good()
	if err := l.Validate(); err != nil {
		t.Fatal(err)
	}
	fpB := "SHA256:" + strings.Repeat("B", 43)
	for name, change := range map[string]func(*AuthorityList){
		"version":      func(l *AuthorityList) { l.V = 2 },
		"trust domain": func(l *AuthorityList) { l.TrustDomain = "example" },
		"serial 0":     func(l *AuthorityList) { l.Serial = 0 },
		"serial big":   func(l *AuthorityList) { l.Serial = MaxListSerial + 1 },
		"no instance":  func(l *AuthorityList) { l.Authorities = nil },
		"bad key":      func(l *AuthorityList) { l.Authorities[0].Key = "SHA256:x" },
		"key twice":    func(l *AuthorityList) { l.Authorities = append(l.Authorities, l.Authorities[0]) },
		"no URL":       func(l *AuthorityList) { l.Authorities[0].URLs = nil },
		"URL twice": func(l *AuthorityList) {
			l.Authorities[0].URLs = []string{"https://192.0.2.10:7432", "https://192.0.2.10:7432"}
		},
		"too many URLs": func(l *AuthorityList) {
			for i := range MaxAuthorityURLs {
				l.Authorities[0].URLs = append(l.Authorities[0].URLs, "https://192.0.2.10:"+string(rune('1'+i))+"000")
			}
		},
		"too many instances": func(l *AuthorityList) {
			for range MaxListedAuthorities {
				l.Authorities = append(l.Authorities, ListedAuthority{Key: fpB, URLs: []string{"https://192.0.2.11:7432"}})
			}
		},
	} {
		l := good()
		change(&l)
		if err := l.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a, b := good(), good()
	if !a.Same(&b) || !a.Lists(fpA) || a.Lists(fpB) {
		t.Fatal("Same or Lists")
	}
	b.Authorities[0].URLs = slices.Clone(b.Authorities[0].URLs)
	slices.Reverse(b.Authorities[0].URLs)
	if a.Same(&b) {
		t.Error("URLs in another order are the same list")
	}
}

func TestPaths(t *testing.T) {
	overlay := DefaultOverlayPrefixes
	urls := []string{
		"https://100.64.0.10:7432",         // 0 overlay v4
		"https://[fd7a:115c:a1e0::a]:7432", // 1 overlay v6
		"https://192.0.2.10:7432",          // 2 v4
		"https://[2001:db8::10]:7432",      // 3 v6
		"https://lii-0.example.com:7432",   // 4 name
		"https://127.0.0.1:7432",           // 5 loopback
	}
	addrs := func(s ...string) []netip.Addr {
		var out []netip.Addr
		for _, a := range s {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	for _, c := range []struct {
		name  string
		addrs []netip.Addr
		want  []int
	}{
		{"tailnet and IPv4", addrs("100.101.102.103", "198.51.100.20", "fe80::1", "127.0.0.1"), []int{0, 1, 2, 4, 5}},
		{"IPv4 only", addrs("198.51.100.20"), []int{2, 4, 5}},
		{"IPv6 only", addrs("2001:db8::20"), []int{3, 4, 5}},
		{"tailnet only", addrs("fd7a:115c:a1e0::20"), []int{0, 1, 4, 5}},
	} {
		p := PathsFrom(c.addrs, overlay)
		if got := p.Order(urls, 0, overlay); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	p := PathsFrom(addrs("198.51.100.20"), overlay)
	if got := p.Order(urls, 4, overlay); !slices.Equal(got, []int{4, 2, 5}) {
		t.Errorf("last good URL first: %v", got)
	}
	if got := p.Order(urls[:2], 0, overlay); !slices.Equal(got, []int{0, 1}) {
		t.Errorf("nothing fits, everything is tried: %v", got)
	}
}
