package daemon

import "testing"

// The example configuration loads.
func TestExampleConfig(t *testing.T) {
	c, err := LoadConfig("../../examples/ergosumd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Authorities) != 1 || len(c.Authorities[0].urls()) != 2 {
		t.Fatalf("authorities %+v", c.Authorities)
	}
}

// The default paths are those that deploy/install.sh creates: on macOS
// below /var/db/ergosum, elsewhere in /var/lib and /run.
func TestDefaultPaths(t *testing.T) {
	for goos, want := range map[string][2]string{
		"linux":  {"/var/lib/ergosum", "/run/ergosum/token"},
		"darwin": {"/var/db/ergosum/state", "/var/db/ergosum/token"},
	} {
		if s, f := defaultPaths(goos); s != want[0] || f != want[1] {
			t.Errorf("%s: state %s, token %s; want %s, %s", goos, s, f, want[0], want[1])
		}
	}
}
