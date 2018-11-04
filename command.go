package proxyprotocol

// Command indicates the PROXY command being used.
type Command byte

const (
	// CommandLocal indicates the connection was established on purpose by the proxy without being relayed.
	CommandLocal Command = 0x00

	// CommandProxy the connection was established on behalf of another node, and reflects the original connection endpoints.
	CommandProxy Command = 0x01
)
