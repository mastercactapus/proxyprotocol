package proxyprotocol

import (
	"log"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func ExampleNewListener() {
	nl, err := net.Listen("tcp", ":80")
	if err != nil {
		log.Println("ERROR: listen:", err)
		return
	}
	defer nl.Close()

	// Wrap listener with 3 second timeout for PROXY header
	l := NewListener(nl, 3*time.Second)

	for {
		c, err := l.Accept()
		if err != nil {
			log.Println("ERROR: accept:", err)
			return
		}

		// RemoteAddr will be the source address of the PROXY header
		log.Println("New connection from:", c.RemoteAddr().String())
	}
}

func TestListener_TCPV1(t *testing.T) {
	nl, err := net.Listen("tcp", ":0")
	assert.NoError(t, err)
	defer nl.Close()

	l := NewListener(nl, time.Second)

	errCh := make(chan error, 2)
	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()

		HeaderV1{
			SrcIP:    net.ParseIP("192.168.0.1"),
			DestIP:   net.ParseIP("192.168.0.2"),
			SrcPort:  1234,
			DestPort: 5678,
		}.WriteTo(c)
	}()
	go func() {
		c, err := l.Accept()
		if err != nil {
			errCh <- err
		}
		connCh <- c
	}()

	timeout := time.NewTimer(time.Second)
	select {
	case <-timeout.C:
		t.Error("timeout waiting for connection")
	case err := <-errCh:
		t.Error(err)
	case c := <-connCh:
		assert.Equal(t, "192.168.0.1:1234", c.RemoteAddr().String(), "SrcAddr")
		assert.Equal(t, "192.168.0.2:5678", c.LocalAddr().String(), "DestAddr")
	}

}

func TestListener_TCPV2(t *testing.T) {
	nl, err := net.Listen("tcp", ":0")
	assert.NoError(t, err)
	defer nl.Close()

	l := NewListener(nl, time.Second)

	errCh := make(chan error, 2)
	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()

		HeaderV2{
			Command: CmdProxy,
			Src:     &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 1234},
			Dest:    &net.TCPAddr{IP: net.ParseIP("192.168.0.2"), Port: 5678},
		}.WriteTo(c)
	}()
	go func() {
		c, err := l.Accept()
		if err != nil {
			errCh <- err
		}
		connCh <- c
	}()

	timeout := time.NewTimer(time.Second)
	select {
	case <-timeout.C:
		t.Error("timeout waiting for connection")
	case err := <-errCh:
		t.Error(err)
	case c := <-connCh:
		assert.Equal(t, "192.168.0.1:1234", c.RemoteAddr().String(), "SrcAddr")
		assert.Equal(t, "192.168.0.2:5678", c.LocalAddr().String(), "DestAddr")
	}

}
