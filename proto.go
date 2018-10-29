package proxyprotocol

// Proto indicates the used transport protocol.
type Proto byte

const (
	// ProtoUnspec indicates the connection is forwarded for an unknown, unspecified or unsupported protocol.
	ProtoUnspec Proto = 0x00

	// ProtoStream indicates the forwarded connection uses a SOCK_STREAM protocol (eg: TCP or UNIX_STREAM).
	ProtoStream Proto = 0x01

	// ProtoDGram indicates the forwarded connection uses a SOCK_DGRAM protocol (eg: UDP or UNIX_DGRAM).
	ProtoDGram Proto = 0x02
)
