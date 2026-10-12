//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "hookmon-smoketest requires Linux")
	os.Exit(1)
}
