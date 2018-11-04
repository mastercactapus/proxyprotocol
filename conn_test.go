package proxyprotocol

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func ExampleHeaderV2_proxy() {
	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Println("ERROR: listen:", err)
		return
	}
	defer l.Close()

	var hdr HeaderV2
	c, err := l.Accept()
	if err != nil {
		log.Println("ERROR: accept:", err)
		return
	}
	defer c.Close()

	// Populate hdr from the new incomming connection.
	hdr.FromConn(c, false)

	// Example target
	//
	// This server will be sent a PROXY header.
	dst, err := net.Dial("tcp", "192.168.0.2:12345")
	if err != nil {
		log.Println("ERROR: connect:", err)
		return
	}
	defer dst.Close()

	// This will write the PROXY header to the backend server.
	_, err = hdr.WriteTo(dst)
	if err != nil {
		log.Println("ERROR: write header:", err)
		return
	}
}

func ExampleHeaderV1_proxy() {
	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Println("ERROR: listen:", err)
		return
	}
	defer l.Close()

	var hdr HeaderV1
	c, err := l.Accept()
	if err != nil {
		log.Println("ERROR: accept:", err)
		return
	}
	defer c.Close()

	// Populate hdr from the new incomming connection.
	hdr.FromConn(c, false)

	// Example target
	//
	// This server will be sent a PROXY header.
	dst, err := net.Dial("tcp", "192.168.0.2:12345")
	if err != nil {
		log.Println("ERROR: connect:", err)
		return
	}
	defer dst.Close()

	// This will write the PROXY header to the backend server.
	_, err = hdr.WriteTo(dst)
	if err != nil {
		log.Println("ERROR: write header:", err)
		return
	}
}

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
			if hdr.SrcAddr() != nil {
				assert.NotNil(t, hdrOut.SrcAddr())
				assert.Equal(t, hdr.SrcAddr().String(), hdrOut.SrcAddr().String(), "SrcAddr")
			} else {
				assert.Nil(t, hdrOut.SrcAddr())
			}
			if hdr.DestAddr() != nil {
				assert.NotNil(t, hdrOut.DestAddr())
				assert.Equal(t, hdr.DestAddr().String(), hdrOut.DestAddr().String(), "DestAddr")
			} else {
				assert.Nil(t, hdrOut.SrcAddr())
			}
		})
	}
	check("V1-IPv4", &HeaderV1{
		SrcPort:  1234,
		DestPort: 5678,
		SrcIP:    net.ParseIP("192.168.0.1"),
		DestIP:   net.ParseIP("192.168.0.2"),
	})
	check("V1-IPv6", &HeaderV1{
		SrcPort:  1234,
		DestPort: 5678,
		SrcIP:    net.ParseIP("2001:db8:85a3::8a2e:370:7334"),
		DestIP:   net.ParseIP("2002:db8:85a3::8a2e:370:7334"),
	})

	check("V2-tcp4", &HeaderV2{
		Command: CmdProxy,
		Src:     &net.TCPAddr{Port: 1234, IP: net.ParseIP("192.168.0.1")},
		Dest:    &net.TCPAddr{Port: 5678, IP: net.ParseIP("192.168.0.2")},
	})
	check("V2-tcp6", &HeaderV2{
		Command: CmdProxy,
		Src:     &net.TCPAddr{Port: 1234, IP: net.ParseIP("2::3")},
		Dest:    &net.TCPAddr{Port: 5678, IP: net.ParseIP("4::5")},
	})
	check("V2-udp4", &HeaderV2{
		Command: CmdProxy,
		Src:     &net.UDPAddr{Port: 1234, IP: net.ParseIP("192.168.0.1")},
		Dest:    &net.UDPAddr{Port: 5678, IP: net.ParseIP("192.168.0.2")},
	})
	check("V2-udp6", &HeaderV2{
		Command: CmdProxy,
		Src:     &net.UDPAddr{Port: 1234, IP: net.ParseIP("2::3")},
		Dest:    &net.UDPAddr{Port: 5678, IP: net.ParseIP("4::5")},
	})
	check("V2-unix", &HeaderV2{
		Command: CmdProxy,
		Src:     &net.UnixAddr{Net: "unix", Name: "foo"},
		Dest:    &net.UnixAddr{Net: "unix", Name: "bar"},
	})
	check("V2-unixgram", &HeaderV2{
		Command: CmdProxy,
		Src:     &net.UnixAddr{Net: "unixgram", Name: "foo"},
		Dest:    &net.UnixAddr{Net: "unixgram", Name: "bar"},
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
