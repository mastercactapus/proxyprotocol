package proxyprotocol

// AddrFamily represents an address family in protocol version 2.
type AddrFamily byte

const (
	// AddrFamilyUnspec means the connection is forwarded for an unknown, unspecified or unsupported protocol.
	AddrFamilyUnspec AddrFamily = 0x00

	// AddrFamilyInet is used when the forwarded connection uses the AF_INET address family (IPv4).
	AddrFamilyInet AddrFamily = 0x01

	// AddrFamilyInet6 is used when the forwarded connection uses the AF_INET6 address family (IPv6).
	AddrFamilyInet6 AddrFamily = 0x02

	// AddrFamilyUnix is used when the forwarded connection uses the AF_UNIX address family (UNIX).
	AddrFamilyUnix AddrFamily = 0x03
)
