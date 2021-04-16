package proxyprotocol

import (
	"errors"
	"io"
)

var (
	sigV1 = []byte("PROXY %s %s %s %d %d\r\n")
	sigV2 = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
)

// InvalidHeaderErr contains the parsing error as well as all data read from the reader.
type InvalidHeaderErr struct {
	error
	Read []byte
}

// Parse will parse detect and return a V1 or V2 header, otherwise InvalidHeaderErr is returned.
func Parse(r io.Reader) (Header, error) {
	buf := make([]byte, 12, 232)

	// both header types are a min of 12 bytes
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}

	switch buf[0] {
	case sigV1[0]:
		return parseV1(buf, r)
	case sigV2[0]:
		return parseV2(buf, r)
	}

	return nil, &InvalidHeaderErr{Read: buf, error: errors.New("invalid signature")}
}
