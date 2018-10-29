package proxyprotocol

import (
	"net"
	"sort"
	"time"
)

// Rule contains configuration for a single subnet.
type Rule struct {
	// Subnet is used to match incomming IP addresses against this rule.
	Subnet *net.IPNet

	// Timeout indicates the max amount of time to receive the PROXY header before
	// terminating the connection.
	Timeout time.Duration
}

// Listener wraps a net.Listener automatically wrapping new connections with PROXY protocol support.
type Listener struct {
	net.Listener

	rules []*Rule
	index map[string]*Rule
}

// NewListener will wrap nl, automatically handling PROXY headers for any matching Rule.
func NewListener(nl net.Listener, rules []Rule) *Listener {
	l := &Listener{
		Listener: nl,
		index:    make(map[string]*Rule, len(rules)),
		rules:    make([]*Rule, 0, len(rules)),
	}
	l.AddRules(rules)
	return l
}

// Accept waits for and returns the next connection to the listener, wrapping it with NewConn if the RemoteAddr matches
// any registered rules.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
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
	for _, n := range l.rules {
		if n.Subnet.Contains(remoteIP) {
			if n.Timeout == 0 {
				return NewConn(c, time.Time{}), nil
			}
			return NewConn(c, time.Now().Add(n.Timeout)), nil
		}
	}
	return c, nil
}

// AddRules will merge the provides rules to the listener. Rules are matched most-specific first.
// If 2 rules have the same subnet, the lower timeout is used and the rules are merged.
func (l *Listener) AddRules(rules []Rule) {
	for _, n := range rules {
		name := n.Subnet.String()
		if s, ok := l.index[name]; ok {
			if n.Timeout > 0 && n.Timeout < s.Timeout {
				s.Timeout = n.Timeout
			}
			continue
		}

		cpy := n
		l.index[name] = &cpy
		l.rules = append(l.rules, &cpy)
	}
	// sort most-specific first
	sort.Slice(l.rules, func(i, j int) bool {
		iOnes, iBits := l.rules[i].Subnet.Mask.Size()
		jOnes, jBits := l.rules[j].Subnet.Mask.Size()
		if iOnes == jOnes {
			return iBits > jBits
		}
		return iOnes > jOnes
	})
}
