package proxyprotocol

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConn_ProxyHeader(t *testing.T) {
	check := func(name string, hdr Header) {
		t.Run(name, func(t *testing.T) {
			src, dst := net.Pipe()
			defer src.Close()
			defer dst.Close()
			dstC := NewConn(dst, time.Now().Add(time.Second))
			go hdr.WriteTo(src)

			hdrOut, err := dstC.ProxyHeader()
			assert.NoError(t, err)
			assert.Equal(t, hdr.Version(), hdrOut.Version())
			if hdr.Source() != nil {
				assert.NotNil(t, hdrOut.Source())
				assert.Equal(t, hdr.Source().String(), hdrOut.Source().String(), "SrcAddr")
			} else {
				assert.Nil(t, hdrOut.Source())
			}
			if hdr.Dest() != nil {
				assert.NotNil(t, hdrOut.Dest())
				assert.Equal(t, hdr.Dest().String(), hdrOut.Dest().String(), "DestAddr")
			} else {
				assert.Nil(t, hdrOut.Source())
			}
		})
	}
	check("V1-IPv4", &HeaderV1{
		SourcePort: 1234,
		DestPort:   5678,
		SourceIP:   net.ParseIP("192.168.0.1"),
		DestIP:     net.ParseIP("192.168.0.2"),
	})
	check("V1-IPv6", &HeaderV1{
		SourcePort: 1234,
		DestPort:   5678,
		SourceIP:   net.ParseIP("2001:db8:85a3::8a2e:370:7334"),
		DestIP:     net.ParseIP("2002:db8:85a3::8a2e:370:7334"),
	})

	check("V2-tcp4", &HeaderV2{
		Command:    CommandProxy,
		SourceAddr: &net.TCPAddr{Port: 1234, IP: net.ParseIP("192.168.0.1")},
		DestAddr:   &net.TCPAddr{Port: 5678, IP: net.ParseIP("192.168.0.2")},
	})
	check("V2-tcp6", &HeaderV2{
		Command:    CommandProxy,
		SourceAddr: &net.TCPAddr{Port: 1234, IP: net.ParseIP("2::3")},
		DestAddr:   &net.TCPAddr{Port: 5678, IP: net.ParseIP("4::5")},
	})
	check("V2-udp4", &HeaderV2{
		Command:    CommandProxy,
		SourceAddr: &net.UDPAddr{Port: 1234, IP: net.ParseIP("192.168.0.1")},
		DestAddr:   &net.UDPAddr{Port: 5678, IP: net.ParseIP("192.168.0.2")},
	})
	check("V2-udp6", &HeaderV2{
		Command:    CommandProxy,
		SourceAddr: &net.UDPAddr{Port: 1234, IP: net.ParseIP("2::3")},
		DestAddr:   &net.UDPAddr{Port: 5678, IP: net.ParseIP("4::5")},
	})
	check("V2-unix", &HeaderV2{
		Command:    CommandProxy,
		SourceAddr: &net.UnixAddr{Net: "unix", Name: "foo"},
		DestAddr:   &net.UnixAddr{Net: "unix", Name: "bar"},
	})
	check("V2-unixgram", &HeaderV2{
		Command:    CommandProxy,
		SourceAddr: &net.UnixAddr{Net: "unixgram", Name: "foo"},
		DestAddr:   &net.UnixAddr{Net: "unixgram", Name: "bar"},
	})
}

func TestNewConnV1(t *testing.T) {
	check := func(name, header, remoteIP, localIP string, remotePort, localPort int) {
		t.Run(name, func(t *testing.T) {
			src, dst := net.Pipe()
			defer src.Close()
			defer dst.Close()

			dstC := NewConn(dst, time.Time{})
			go io.WriteString(src, header)

			local := dstC.LocalAddr()
			if a, ok := local.(*net.TCPAddr); ok {
				assert.Equal(t, localPort, a.Port, "Local Port")
				assert.Equal(t, localIP, a.IP.String(), "Local IP")
			} else {
				t.Errorf("invalid local address type: got %T; want *net.TCPAddr", local)
			}

			remote := dstC.RemoteAddr()
			if a, ok := remote.(*net.TCPAddr); ok {
				assert.Equal(t, remotePort, a.Port, "Remote Port")
				assert.Equal(t, remoteIP, a.IP.String(), "Remote IP")
			} else {
				t.Errorf("invalid remote address type: got %T; want *net.TCPAddr", remote)
			}
		})
	}

	check(
		"IPv4",
		"PROXY TCP4 192.168.0.1 192.168.0.2 1234 5678\r\n",
		"192.168.0.1", "192.168.0.2",
		1234, 5678,
	)
	check(
		"IPv6",
		"PROXY TCP6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 2002:0db8:85a3::8a2e:0370:7334 1234 5678\r\n",
		"2001:db8:85a3::8a2e:370:7334", "2002:db8:85a3::8a2e:370:7334",
		1234, 5678,
	)

}
