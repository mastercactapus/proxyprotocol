package proxyprotocol

// AF represents an address family in protocol version 2.
// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
type AF byte

const (
	// AFUnspec means the connection is forwarded for an unknown, unspecified or unsupported protocol.
	AFUnspec AF = 0x00

	// AFInet is used when the forwarded connection uses the AF_INET address family (IPv4).
	AFInet AF = 0x01

	// AFInet6 is used when the forwarded connection uses the AF_INET6 address family (IPv6).
	AFInet6 AF = 0x02

	// AFUnix is used when the forwarded connection uses the AF_UNIX address family (UNIX).
	AFUnix AF = 0x03
)
