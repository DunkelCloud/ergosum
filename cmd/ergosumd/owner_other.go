//go:build !unix

package main

import "os"

// owner is not available on this platform.
func owner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
