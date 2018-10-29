package proxyprotocol

import (
	"net"
)

// Header provides information decoded from a PROXY header.
type Header interface {
	Version() int
	Source() net.Addr
	Dest() net.Addr
}
