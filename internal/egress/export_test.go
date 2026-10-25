package egress

import "crypto/tls"

// MintLeaf lets external tests use a CA as the upstreams' "public" PKI.
func MintLeaf(c *CA, host string) (*tls.Certificate, error) { return c.leaf(host) }
