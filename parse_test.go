package proxyprotocol

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse_Malformed(t *testing.T) {
	data := []byte{
		// PROXY protocol v2 magic header
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		// v2 version, PROXY cmd
		0x21,
		// TCP, IPv4 (also works with 0x13,0x21,0x22,0x31,0x32)
		0x12,
		// Length
		0x00, 0x00,
		// src/dest address data _should_ be here but is omitted.
	}

	_, err := Parse(
		bufio.NewReader(
			bytes.NewReader(data)))
	assert.Error(t, err)
}
