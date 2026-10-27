// Command ergosum runs the authority (serve) and its operator tooling.
package main

import (
	"fmt"
	"os"

	"github.com/DunkelCloud/ergosum/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("ergosum", version.String())
		return
	}
	fmt.Fprintln(os.Stderr, "usage: ergosum version")
	os.Exit(2)
}
