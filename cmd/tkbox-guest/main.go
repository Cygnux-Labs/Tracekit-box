// Command tkbox-guest is the guest agent, PID 1 inside the micro-VM (init=/sbin/tkbox-guest): it makes the read-only
// image root writable with an overlay, fetches the box's boot config from the host over vsock, mounts the workspace,
// runs the egress forwarder and serves the agent RPC (exec, files, diff, shutdown). See internal/guest.
package main

import (
	"fmt"
	"os"

	"github.com/Cygnux-Labs/tracekit-box/internal/guest"
)

var version = "dev"

func main() {
	// as PID 1 the kernel hands init any unknown cmdline words as argv: never let one make init exit
	if os.Getpid() != 1 && len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("tkbox-guest", version)
		return
	}
	guest.Main(version)
}
