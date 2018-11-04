package proxyprotocol

import (
	"net"
	"sort"
	"sync"
	"time"
)

type rules []Rule

func (r rules) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}
func (r rules) Len() int { return len(r) }
func (r rules) Less(i, j int) bool {
	iOnes, iBits := r[i].Subnet.Mask.Size()
	jOnes, jBits := r[j].Subnet.Mask.Size()
	if iOnes != jOnes {
		return iOnes > jOnes
	}
	if iBits != jBits {
		return iBits > jBits
	}
	if r[i].Timeout != r[j].Timeout {
		if r[j].Timeout == 0 {
			return true
		}
		return r[i].Timeout < r[j].Timeout
	}
	return r[i].Timeout < r[j].Timeout
}

// Listener wraps a net.Listener automatically wrapping new connections with PROXY protocol support.
type Listener struct {
	net.Listener

	filter []Rule
	t      time.Duration

	mx sync.RWMutex
}

// NewListener will wrap nl, automatically handling PROXY headers for all connections.
// To only require PROXY headers from certain connections, use SetFilter.
//
// By default, all connections must provide a PROXY header within the provided timeout.
func NewListener(nl net.Listener, t time.Duration) *Listener {
	l := &Listener{
		Listener: nl,
		t:        t,
	}
	return l
}

// Accept waits for and returns the next connection to the listener, wrapping it with NewConn if the RemoteAddr matches
// any registered rules.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	l.mx.RLock()
	filter := l.filter
	t := l.t
	l.mx.RUnlock()

	if len(filter) == 0 {
		return NewConn(c, time.Now().Add(t)), nil
	}

	var remoteIP net.IP
	switch r := c.RemoteAddr().(type) {
	case *net.TCPAddr:
		remoteIP = r.IP
	case *net.UDPAddr:
		remoteIP = r.IP
	default:
		return c, nil
	}

	for _, n := range filter {
		if n.Subnet.Contains(remoteIP) {
			if n.Timeout == 0 {
				return NewConn(c, time.Time{}), nil
			}
			return NewConn(c, time.Now().Add(n.Timeout)), nil
		}
	}
	return c, nil
}

// SetDefaultTimeout sets the default timeout, used when the subnet filter is nil.
//
// SetDefaultTimeout is safe to call from multiple goroutines while the listener is in use.
func (l *Listener) SetDefaultTimeout(t time.Duration) {
	l.mx.Lock()
	l.t = t
	l.mx.Unlock()
}

// Filter returns the current set of filter rules.
//
// Filter is safe to call from multiple goroutines while the listener is in use.
func (l *Listener) Filter() []Rule {
	l.mx.RLock()
	filter := l.filter
	l.mx.RUnlock()
	f := make([]Rule, len(filter))
	copy(f, filter)
	return f
}

// SetFilter allows limiting PROXY header parsing to matching Subnets with an optional timeout.
// If filter is nil, all connections will be required to provide a PROXY header.
//
// Connections not matching any rule will be returned from Accept from the underlying listener
// directly without reading a PROXY header.
//
// Duplicate subnet rules will automatically be removed and the lowest non-zero timeout will be used.
//
// SetFilter is safe to call from multiple goroutines while the listener is in use.
func (l *Listener) SetFilter(filter []Rule) {
	newFilter := make([]Rule, len(filter))
	copy(newFilter, filter)
	sort.Sort(rules(newFilter))
	if len(newFilter) > 0 {
		// dedup
		last := newFilter[0]
		nf := newFilter[1:1]
		for _, f := range newFilter[1:] {
			if last.Subnet.String() == f.Subnet.String() {
				continue
			}

			last = f
			nf = append(nf, f)
		}
	}

	l.mx.Lock()
	l.filter = newFilter
	l.mx.Unlock()
}
