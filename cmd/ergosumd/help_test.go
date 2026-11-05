package main

import (
	"testing"

	"github.com/DunkelCloud/ergosum/internal/cli/clitest"
)

func TestMain(m *testing.M) { clitest.Main(m, main) }

// TestHelp: every command explains its arguments and flags on -h.
func TestHelp(t *testing.T) {
	for _, c := range []string{"run", "request", "fingerprint", "check", "secret create", "secret get", "secret info"} {
		clitest.Help(t, c)
	}
}
