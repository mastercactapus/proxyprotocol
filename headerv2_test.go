package proxyprotocol

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeaderV2(t *testing.T) {
	type section struct {
		name  string
		value []byte
	}
	check := func(name string, h HeaderV2, exp []section) {
		t.Run(name+"_WriteTo", func(t *testing.T) {
			var buf bytes.Buffer
			_, err := h.WriteTo(&buf)
			assert.NoError(t, err)
			for _, s := range exp {
				cmp := make([]byte, len(s.value))
				_, err := io.ReadFull(&buf, cmp)
				assert.NoError(t, err)
				assert.Equal(t, s.value, cmp, s.name)
			}
		})
		t.Run(name+"_Parse", func(t *testing.T) {
			var buf bytes.Buffer
			for _, s := range exp {
				buf.Write(s.value)
			}
			hdr, err := Parse(bufio.NewReader(&buf))
			assert.NoError(t, err)
			assert.IsType(t, &HeaderV2{}, hdr, "Header Type")
			p := hdr.(*HeaderV2)
			assert.Equal(t, h.Command, p.Command, "Command")
			if h.SourceAddr != nil {
				assert.NotNil(t, p.SourceAddr)
				assert.Equal(t, h.SourceAddr.String(), p.SourceAddr.String(), "SrcAddr")
			} else {
				assert.Nil(t, p.SourceAddr)
			}
			if h.DestAddr != nil {
				assert.NotNil(t, p.DestAddr)
				assert.Equal(t, h.DestAddr.String(), p.DestAddr.String(), "DestAddr")
			} else {
				assert.Nil(t, p.DestAddr)
			}
		})
	}

	check("local", HeaderV2{},
		[]section{
			{name: "Signature", value: sigV2},
			{name: "Version", value: []byte{0x20}},   // v2, Local
			{name: "Fam/Proto", value: []byte{0x00}}, // unspec, unspec
			{name: "Length", value: []byte{0, 0}},    // zero length
		},
	)

	check("tcp-ipv4", HeaderV2{
		Command:    CommandProxy,
		SourceAddr: &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 80},
		DestAddr:   &net.TCPAddr{IP: net.ParseIP("192.168.0.2"), Port: 90},
	},
		[]section{
			{name: "Signature", value: sigV2},
			{name: "Version", value: []byte{0x21}},   // v2, Proxy
			{name: "Fam/Proto", value: []byte{0x11}}, // INET, STREAM
			{name: "Length", value: []byte{0, 12}},   // length=12

			{name: "SrcAddr", value: []byte{192, 168, 0, 1}},
			{name: "DestAddr", value: []byte{192, 168, 0, 2}},

			{name: "SrcPort", value: []byte{0, 80}},
			{name: "DstPort", value: []byte{0, 90}},
		},
	)

	check("udp-ipv4", HeaderV2{
		Command:    CommandProxy,
		SourceAddr: &net.UDPAddr{IP: net.ParseIP("192.168.0.1"), Port: 80},
		DestAddr:   &net.UDPAddr{IP: net.ParseIP("192.168.0.2"), Port: 90},
	},
		[]section{
			{name: "Signature", value: sigV2},
			{name: "Version", value: []byte{0x21}},   // v2, Proxy
			{name: "Fam/Proto", value: []byte{0x12}}, // INET, DGRAM
			{name: "Length", value: []byte{0, 12}},   // length=12

			{name: "SrcAddr", value: []byte{192, 168, 0, 1}},
			{name: "DestAddr", value: []byte{192, 168, 0, 2}},

			{name: "SrcPort", value: []byte{0, 80}},
			{name: "DstPort", value: []byte{0, 90}},
		},
	)

	check("udp-ipv6", HeaderV2{
		Command:    CommandProxy,
		SourceAddr: &net.UDPAddr{IP: net.ParseIP("2001::1"), Port: 80},
		DestAddr:   &net.UDPAddr{IP: net.ParseIP("2002::2"), Port: 90},
	},
		[]section{
			{name: "Signature", value: sigV2},
			{name: "Version", value: []byte{0x21}},   // v2, Proxy
			{name: "Fam/Proto", value: []byte{0x22}}, // INET6, DGRAM
			{name: "Length", value: []byte{0, 36}},   // length=36

			{name: "SrcAddr", value: []byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}},
			{name: "DestAddr", value: []byte{0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}},

			{name: "SrcPort", value: []byte{0, 80}},
			{name: "DstPort", value: []byte{0, 90}},
		},
	)

	check("unixstream", HeaderV2{
		Command:    CommandProxy,
		SourceAddr: &net.UnixAddr{Net: "unix", Name: "foo"},
		DestAddr:   &net.UnixAddr{Net: "unix", Name: "bar"},
	},
		[]section{
			{name: "Signature", value: sigV2},
			{name: "Version", value: []byte{0x21}},   // v2, Proxy
			{name: "Fam/Proto", value: []byte{0x31}}, // UNIX, STREAM
			{name: "Length", value: []byte{0, 216}},  // length=216

			{name: "SrcAddr", value: append([]byte("foo"), make([]byte, 105)...)},
			{name: "DestAddr", value: append([]byte("bar"), make([]byte, 105)...)},
		},
	)

	check("unixgram", HeaderV2{
		Command:    CommandProxy,
		SourceAddr: &net.UnixAddr{Net: "unixgram", Name: "foo"},
		DestAddr:   &net.UnixAddr{Net: "unixgram", Name: "bar"},
	},
		[]section{
			{name: "Signature", value: sigV2},
			{name: "Version", value: []byte{0x21}},   // v2, Proxy
			{name: "Fam/Proto", value: []byte{0x32}}, // UNIX, DGRAM
			{name: "Length", value: []byte{0, 216}},  // length=216

			{name: "SrcAddr", value: append([]byte("foo"), make([]byte, 105)...)},
			{name: "DestAddr", value: append([]byte("bar"), make([]byte, 105)...)},
		},
	)

}
