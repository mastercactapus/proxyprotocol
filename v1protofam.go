package proxyprotocol

// V1ProtoFam represents an address family and transport protocol for PROXY protocol version 1.
type V1ProtoFam string

const (
	// V1ProtoFamUnknown indicates other, unsupported, or unknown protocols.
	V1ProtoFamUnknown V1ProtoFam = "UNKNOWN"

	// V1ProtoFamTCP4 for TCP over IPv4
	V1ProtoFamTCP4 V1ProtoFam = "TCP4"

	// V1ProtoFamTCP6 for TCP over IPv6
	V1ProtoFamTCP6 V1ProtoFam = "TCP6"
)
