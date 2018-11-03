package proxyprotocol

import (
	"io"
	"net"
)

// Header provides information decoded from a PROXY header.
type Header interface {
	Version() int
	Source() net.Addr
	Dest() net.Addr

	WriteTo(io.Writer) (int64, error)
}
