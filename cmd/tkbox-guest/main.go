// Command tkbox-guest is the guest agent, PID 1 inside the micro-VM. STUB: agent B owns this command.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "tkbox-guest: not implemented yet")
	os.Exit(2)
}
