//go:build !linux

package guest

import (
	"fmt"
	"os"
)

// Main is PID 1 inside the Linux micro-VM; there is nothing to run elsewhere.
func Main(version string) {
	fmt.Fprintln(os.Stderr, "tkbox-guest runs only as init inside a Linux micro-VM")
	os.Exit(2)
}
