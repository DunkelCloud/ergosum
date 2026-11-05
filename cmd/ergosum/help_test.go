package main

import (
	"testing"

	"github.com/DunkelCloud/ergosum/internal/cli/clitest"
)

func TestMain(m *testing.M) { clitest.Main(m, main) }

// TestHelp: every command explains its arguments and flags on -h.
func TestHelp(t *testing.T) {
	for _, c := range []string{
		"serve", "unseal", "keygen",
		"journal state", "journal checkpoint", "journal compact", "journal sync", "journal export",
		"bind", "revoke", "show", "list", "authorities",
		"release sign", "release verify",
	} {
		clitest.Help(t, c)
	}
}
