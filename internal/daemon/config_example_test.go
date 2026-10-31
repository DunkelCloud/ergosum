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
