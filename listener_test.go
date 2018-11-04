package proxyprotocol

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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
			SourceIP:   net.ParseIP("192.168.0.1"),
			DestIP:     net.ParseIP("192.168.0.2"),
			SourcePort: 1234,
			DestPort:   5678,
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
			Command:    CommandProxy,
			SourceAddr: &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 1234},
			DestAddr:   &net.TCPAddr{IP: net.ParseIP("192.168.0.2"), Port: 5678},
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
