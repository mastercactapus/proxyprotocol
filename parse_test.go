package proxyprotocol

import (
	"bufio"
	"bytes"
	_ "embed"
	"net"
	"strings"
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

//go:embed header-v2-sample.bin
var sample1 []byte

func TestParse_HeaderV2(t *testing.T) {
	h, err := Parse(bufio.NewReader(bytes.NewReader(sample1)))
	assert.NoError(t, err)

	s, ok := FindTLV(h, PP2TypeNOOP)
	assert.True(t, ok)
	assert.Equal(t, "hello, world!", string(s))
}

func TestParse_HeaderV1(t *testing.T) {
	check := func(name string, hdr HeaderV1, exp string) {
		t.Helper()

		h, err := Parse(bufio.NewReader(strings.NewReader(exp)))
		assert.NoError(t, err, name)
		assert.Equal(t, 1, h.Version(), name+" version")

		h1 := h.(*HeaderV1)
		assert.Equal(t, hdr, *h1, name)
	}

	check("blank", HeaderV1{}, "PROXY UNKNOWN\r\n")
	check("ipv4", HeaderV1{
		SrcPort:  1234,
		DestPort: 5678,
		SrcIP:    net.ParseIP("192.168.0.1"),
		DestIP:   net.ParseIP("192.168.0.2"),
	},
		"PROXY TCP4 192.168.0.1 192.168.0.2 1234 5678\r\n",
	)

	check("ipv6", HeaderV1{
		SrcPort:  1234,
		DestPort: 5678,
		SrcIP:    net.ParseIP("2001:db8:85a3::8a2e:370:7334"),
		DestIP:   net.ParseIP("2002:db8:85a3::8a2e:370:7334"),
	},
		"PROXY TCP6 2001:db8:85a3::8a2e:370:7334 2002:db8:85a3::8a2e:370:7334 1234 5678\r\n",
	)

	check("ipv6-mapped-ipv4", HeaderV1{
		SrcPort:  53740,
		DestPort: 10001,
		SrcIP:    net.ParseIP("::ffff:192.168.0.1"),
		DestIP:   net.ParseIP("::ffff:192.168.0.1"),
	},
		"PROXY TCP6 ::ffff:192.168.0.1 ::ffff:192.168.0.1 53740 10001\r\n",
	)
}
