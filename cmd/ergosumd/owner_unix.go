//go:build unix

package main

import (
	"os"
	"syscall"
)

// owner returns the user and group that own a file.
func owner(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
