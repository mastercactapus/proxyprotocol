package proxyprotocol

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeaderV1_WriteTo(t *testing.T) {
	check := func(name string, hdr HeaderV1, exp string) {
		t.Run(name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			_, err := hdr.WriteTo(buf)
			assert.NoError(t, err)
			assert.Equal(t, exp, buf.String())
		})
	}

	check("blank", HeaderV1{}, "PROXY UNKNOWN <nil> <nil> 0 0\r\n")
	check("ipv4", HeaderV1{
		SourcePort: 1234,
		DestPort:   5678,
		SourceIP:   net.ParseIP("192.168.0.1"),
		DestIP:     net.ParseIP("192.168.0.2"),
	},
		"PROXY TCP4 192.168.0.1 192.168.0.2 1234 5678\r\n",
	)
	check("ipv4-fam-override", HeaderV1{
		SourcePort: 1234,
		DestPort:   5678,
		Family:     V1ProtoFamUnknown,
		SourceIP:   net.ParseIP("192.168.0.1"),
		DestIP:     net.ParseIP("192.168.0.2"),
	},
		"PROXY UNKNOWN 192.168.0.1 192.168.0.2 1234 5678\r\n",
	)
	check("ipv6", HeaderV1{
		SourcePort: 1234,
		DestPort:   5678,
		SourceIP:   net.ParseIP("2001:db8:85a3::8a2e:370:7334"),
		DestIP:     net.ParseIP("2002:db8:85a3::8a2e:370:7334"),
	},
		"PROXY TCP6 2001:db8:85a3::8a2e:370:7334 2002:db8:85a3::8a2e:370:7334 1234 5678\r\n",
	)

}
