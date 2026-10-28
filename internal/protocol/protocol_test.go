package protocol

import "testing"

func TestValidDNSName(t *testing.T) {
	good := []string{"host1.example.com", "a.b", "x-1.example.com", "host1.tailnet.example.com", "1a.example.com"}
	for _, s := range good {
		if !ValidDNSName(s) {
			t.Errorf("%q rejected", s)
		}
	}
	bad := []string{
		"", "host1", "Host1.example.com", "host1..example.com", "host1.example.com.",
		"-a.example.com", "a-.example.com", "a b.example.com", "host_1.example.com",
		"100.64.0.5", "192.0.2.10", "host.123", "2001:db8::10", "[2001:db8::10]",
	}
	for _, s := range bad {
		if ValidDNSName(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestParseAddresses(t *testing.T) {
	addrs, err := ParseAddresses([]string{"192.0.2.10", "::ffff:198.51.100.20", "2001:DB8::10"})
	if err != nil {
		t.Fatal(err)
	}
	if got := addrs[1].String(); got != "198.51.100.20" {
		t.Fatalf("4-in-6 not unmapped: %s", got)
	}
	if got := addrs[2].String(); got != "2001:db8::10" {
		t.Fatalf("not canonical: %s", got)
	}
	for _, in := range [][]string{{"fe80::1%eth0"}, {"192.0.2"}, make([]string, MaxAddresses+1)} {
		if _, err := ParseAddresses(in); err == nil {
			t.Errorf("%v accepted", in)
		}
	}
}
