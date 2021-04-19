package proxyprotocol

import (
	"bufio"
	"net"
	"sync"
	"time"
)

// Conn wraps a net.Conn using the PROXY protocol to determin LocalAddr() and RemoteAddr().
type Conn struct {
	net.Conn
	err          error
	once         sync.Once
	r            *bufio.Reader
	deadline     time.Time
	nextDeadline time.Time
	hdr          Header

	local, remote net.Addr
}

type wrappedConn struct {
	net.Conn
	hdr Header
}

func (w *wrappedConn) LocalAddr() net.Addr          { return w.hdr.DestAddr() }
func (w *wrappedConn) RemoteAddr() net.Addr         { return w.hdr.SrcAddr() }
func (w *wrappedConn) ProxyHeader() (Header, error) { return w.hdr, nil }

// NewConn will wrap an existing net.Conn using `deadline` to receive the header.
//
// Deprecated: Use WrapConn instead.
func NewConn(c net.Conn, deadline time.Time) *Conn {
	return &Conn{
		Conn:     c,
		deadline: deadline,
		r:        bufio.NewReader(c),
	}
}

// WrapConn will return a new net.Conn with LocalAddr and RemoteAddr set to
// the appropriate values from the PROXY protocol. The header is read and parsed
// before returning (call SetReadDeadline on c before calling WrapConn if necessary).
//
// The original net.Conn is returned if there is an error.
func WrapConn(c net.Conn) (net.Conn, error) {
	hdr, err := Parse(c)
	if err != nil {
		return c, err
	}
	return &wrappedConn{
		Conn: c,
		hdr:  hdr,
	}, nil
}

// ProxyHeader will return the PROXY header received on the current connection.
func (c *Conn) ProxyHeader() (Header, error) {
	c.once.Do(c.parse)
	return c.hdr, c.err
}

func (c *Conn) parse() {
	if !c.deadline.IsZero() && (c.nextDeadline.IsZero() || c.nextDeadline.After(c.deadline)) {
		// deadline passed to NewConn and SetDeadline hasn't been called
		// with a sooner time
		c.Conn.SetReadDeadline(c.deadline)
		defer c.Conn.SetReadDeadline(c.nextDeadline)
	}

	c.hdr, c.err = Parse(c.r)
	if c.err != nil {
		return
	}

	c.local = c.hdr.DestAddr()
	c.remote = c.hdr.SrcAddr()
}

// SetDeadline calls SetDeadline on the underlying net.Conn.
func (c *Conn) SetDeadline(t time.Time) error {
	c.nextDeadline = t
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline calls SetReadDeadline on the underlying net.Conn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.nextDeadline = t
	return c.Conn.SetReadDeadline(t)
}

// RemoteAddr returns the remote network address provided by the PROXY header.
func (c *Conn) RemoteAddr() net.Addr {
	c.once.Do(c.parse)
	if c.err != nil || c.remote == nil {
		return c.Conn.RemoteAddr()
	}
	return c.remote
}

// LocalAddr returns the local network address provided by the PROXY header.
func (c *Conn) LocalAddr() net.Addr {
	c.once.Do(c.parse)
	if c.err != nil || c.local == nil {
		return c.Conn.LocalAddr()
	}
	return c.local
}

// Read reads data from the connection, after parsing the PROXY header.
func (c *Conn) Read(p []byte) (int, error) {
	c.once.Do(c.parse)
	if c.err != nil {
		return 0, c.err
	}
	return c.r.Read(p)
}
