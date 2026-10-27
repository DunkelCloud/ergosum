// Command ergosumd is the machine identity daemon. It holds the machine's
// key pair, requests identity tokens from an authority and answers the
// authority's callbacks.
package main

import (
	"fmt"
	"os"

	"github.com/DunkelCloud/ergosum/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("ergosumd", version.String())
		return
	}
	fmt.Fprintln(os.Stderr, "usage: ergosumd version")
	os.Exit(2)
}
