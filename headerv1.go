package proxyprotocol

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
)

// HeaderV1 contains information relayed by the PROXY protocol version 1 (human-readable) header.
type HeaderV1 struct {
	Family     V1ProtoFam
	SourcePort int
	SourceIP   net.IP
	DestPort   int
	DestIP     net.IP
}

func parseV1(r *bufio.Reader) (*HeaderV1, error) {
	buf := make([]byte, 0, 108)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, &InvalidHeaderErr{Read: buf, error: err}
		}
		buf = append(buf, b)
		if b == '\n' {
			break
		}
		if len(buf) == 108 {
			return nil, &InvalidHeaderErr{Read: buf, error: errors.New("header too long")}
		}
	}
	var fam V1ProtoFam
	var srcIPStr, dstIPStr string
	var srcPort, dstPort int
	n, err := fmt.Sscanf(string(buf), string(sigV1), &fam, &srcIPStr, &dstIPStr, &srcPort, &dstPort)
	if n == 0 && err != nil {
		return nil, &InvalidHeaderErr{Read: buf, error: err}
	}
	switch fam {
	case V1ProtoFamUnknown:
		return &HeaderV1{Family: fam}, nil
	case V1ProtoFamTCP4, V1ProtoFamTCP6:
		// couldn't parse IP/port
		if err != nil {
			return nil, &InvalidHeaderErr{Read: buf, error: err}
		}
	default:
		return nil, &InvalidHeaderErr{Read: buf, error: errors.New("unsupported INET protocol/family")}
	}

	srcIP := net.ParseIP(srcIPStr)
	if srcIP == nil {
		return nil, &InvalidHeaderErr{Read: buf, error: errors.New("invalid source address")}
	}
	dstIP := net.ParseIP(dstIPStr)
	if dstIP == nil {
		return nil, &InvalidHeaderErr{Read: buf, error: errors.New("invalid destination address")}
	}

	return &HeaderV1{
		Family:     fam,
		SourceIP:   srcIP,
		DestIP:     dstIP,
		SourcePort: srcPort,
		DestPort:   dstPort,
	}, nil
}

// FromConn will populate header data from the given net.Conn.
// It is assumed the connection is incomming, and the header is set to proxy
// details forward.
//
// Specifically, the RemoteAddr of the Conn will be considered the Source address/port
// and the LocalAddr of the Conn will be considered the Destination address/port for
// the purposes of the PROXY header.
func (h *HeaderV1) FromConn(c net.Conn) error {
	local, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		return errors.New("unsupported local address type")
	}
	remote, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return errors.New("unsupported remote address type")
	}
	if remote.IP.To4() != nil {
		h.Family = V1ProtoFamTCP4
	} else {
		h.Family = V1ProtoFamTCP6
	}
	h.SourceIP = remote.IP
	h.SourcePort = remote.Port
	h.DestIP = local.IP
	h.DestPort = local.Port
	return nil
}

// Version always returns 1.
func (HeaderV1) Version() int { return 1 }

// Source returns the TCP source address.
func (h HeaderV1) Source() net.Addr { return &net.TCPAddr{IP: h.SourceIP, Port: h.SourcePort} }

// Dest returns the TCP destination address.
func (h HeaderV1) Dest() net.Addr { return &net.TCPAddr{IP: h.DestIP, Port: h.DestPort} }

// WriteTo will write the V1 header to w.
func (h HeaderV1) WriteTo(w io.Writer) (int64, error) {
	if h.Family == "" {
		if h.SourceIP.To4() != nil {
			h.Family = V1ProtoFamTCP4
		} else if h.SourceIP.To16() != nil {
			h.Family = V1ProtoFamTCP6
		} else {
			h.Family = V1ProtoFamUnknown
		}
	}
	n, err := fmt.Fprintf(w, "PROXY %s %s %s %d %d\r\n",
		h.Family,
		h.SourceIP.String(),
		h.DestIP.String(),
		h.SourcePort,
		h.DestPort,
	)
	return int64(n), err
}
