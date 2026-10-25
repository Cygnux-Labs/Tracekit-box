// Package guest is the guest agent that runs as PID 1 inside the micro-VM: init (mounts, overlay root, reaping),
// boot-config fetch, the agent RPC server on vsock proto.PortAgent, exec, files, workspace diff and the egress
// forwarder. STUB: agent B owns this package.
package guest
