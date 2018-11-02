package proxyprotocol

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConn_ProxyHeader(t *testing.T) {
	t.Run("V1", func(t *testing.T) {
		hdr := &HeaderV1{
			SourcePort: 1234,
			DestPort:   5678,
			Family:     V1ProtoFamTCP4,
			SourceIP:   net.ParseIP("192.168.0.1"),
			DestIP:     net.ParseIP("192.168.0.2"),
		}

		src, dst := net.Pipe()
		defer src.Close()
		defer dst.Close()
		dstC := NewConn(dst, time.Time{})
		go hdr.WriteTo(src)

		hdrOut, err := dstC.ProxyHeader()
		assert.NoError(t, err)
		assert.Equal(t, hdr, hdrOut)
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
