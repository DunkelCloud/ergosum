package authority

import (
	"fmt"
	"os"
	"runtime"
)

// checkKeyMode refuses a signing key that other users may read, or that
// anyone but its owner may change: on a shared host, a daemon or another
// service that is taken over must not get at it. Windows has no such mode
// bits.
func checkKeyMode(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if m := fi.Mode().Perm(); m&0o027 != 0 {
		return fmt.Errorf("signing key %s has mode %04o: other users could read or change it; chmod 0600, or 0640 with the group ergosum-authority", path, m)
	}
	return nil
}
