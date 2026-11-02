package authority

import (
	"fmt"
	"os"
	"runtime"
)

// checkKeyMode refuses a key file (the signing key, the exchange key) that
// other users may read, or that anyone but its owner may change: on a
// shared host, a daemon or another service that is taken over must not get
// at it. Windows has no such mode bits.
func checkKeyMode(what, path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if m := fi.Mode().Perm(); m&0o027 != 0 {
		return fmt.Errorf("%s %s has mode %04o: other users could read or change it; chmod 0600, or 0640 with the group ergosum-authority", what, path, m)
	}
	return nil
}
