package proxyprotocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Header provides information decoded from a PROXY header.
type Header interface {
	Version() int
	Source() net.Addr
	Dest() net.Addr
}

// HeaderV1 contains information relayed by the PROXY protocol version 1 (human-readable) header.
type HeaderV1 struct {
	Family     string
	SourcePort int
	SourceIP   net.IP
	DestPort   int
	DestIP     net.IP
}

// Version always returns 1.
func (HeaderV1) Version() int { return 1 }

// Source returns the TCP source address.
func (h HeaderV1) Source() net.Addr { return &net.TCPAddr{IP: h.SourceIP, Port: h.SourcePort} }

// Dest returns the TCP destination address.
func (h HeaderV1) Dest() net.Addr { return &net.TCPAddr{IP: h.DestIP, Port: h.DestPort} }

// WriteTo will write the V1 header to w.
func (h HeaderV1) WriteTo(w io.Writer) (int64, error) {
	n, err := fmt.Fprintf(w, "PROXY %s %s %s %d %d\r\n",
		h.Family,
		h.SourceIP.String(),
		h.DestIP.String(),
		h.SourcePort,
		h.DestPort,
	)
	return int64(n), err
}

// HeaderV2 contains information relayed by the PROXY protocol version 2 (binary) header.
type HeaderV2 struct {
	Command    Command
	Family     AF
	Protocol   Proto
	SourceAddr net.Addr
	DestAddr   net.Addr
	Trailing   []byte
}

// Version always returns 2.
func (HeaderV2) Version() int { return 2 }

// Source returns the source address as TCP, UDP, Unix, or nil depending on Protocol and Family.
func (h HeaderV2) Source() net.Addr { return h.SourceAddr }

// Dest returns the destination address as TCP, UDP, Unix, or nil depending on Protocol and Family.
func (h HeaderV2) Dest() net.Addr { return h.DestAddr }

// WriteTo will write the V2 header to w.
func (h HeaderV2) WriteTo(w io.Writer) (int64, error) {
	var rawHdr rawV2
	copy(rawHdr.Sig[:], sigV2)
	rawHdr.VerCmd = (2 << 4) | (0xf & byte(h.Command))
	rawHdr.FamProto = (byte(h.Family) << 4) | (0xf & byte(h.Protocol))

	addr := make([]byte, 216)

	setAddr := func(srcIP, dstIP net.IP, srcPort, dstPort, ipLen int) error {
		if len(srcIP) != ipLen {
			return errors.New("invalid source address")
		}
		if len(dstIP) != ipLen {
			return errors.New("invalid destination address")
		}
		buf := bytes.NewBuffer(addr[:0])
		buf.Write(srcIP)
		buf.Write(dstIP)
		binary.Write(buf, binary.BigEndian, uint16(srcPort))
		binary.Write(buf, binary.BigEndian, uint16(dstPort))
		addr = buf.Bytes()
		return nil
	}

	switch rawHdr.FamProto {
	case 0x11: // TCP over IPv4
		src, _ := h.SourceAddr.(*net.TCPAddr)
		dst, _ := h.DestAddr.(*net.TCPAddr)
		setAddr(src.IP, dst.IP, src.Port, dst.Port, 4)
	case 0x12: // UDP over IPv4
		src, _ := h.SourceAddr.(*net.UDPAddr)
		dst, _ := h.DestAddr.(*net.UDPAddr)
		setAddr(src.IP, dst.IP, src.Port, dst.Port, 4)
	case 0x21: // TCP over IPv6
		src, _ := h.SourceAddr.(*net.TCPAddr)
		dst, _ := h.DestAddr.(*net.TCPAddr)
		setAddr(src.IP, dst.IP, src.Port, dst.Port, 16)
	case 0x22: // UDP over IPv6
		src, _ := h.SourceAddr.(*net.UDPAddr)
		dst, _ := h.DestAddr.(*net.UDPAddr)
		setAddr(src.IP, dst.IP, src.Port, dst.Port, 16)
	case 0x31: // UNIX stream
		src, ok := h.SourceAddr.(*net.UnixAddr)
		if !ok || src.Net != "unix" || len(src.Name) > 108 {
			return 0, errors.New("invalid source address")
		}
		dst, ok := h.SourceAddr.(*net.UnixAddr)
		if !ok || dst.Net != "unix" || len(dst.Name) > 108 {
			return 0, errors.New("invalid destination address")
		}
		copy(addr, src.Name)
		copy(addr[108:], dst.Name)
	case 0x32: // UNIX datagram
		src, ok := h.SourceAddr.(*net.UnixAddr)
		if !ok || src.Net != "unixgram" || len(src.Name) > 108 {
			return 0, errors.New("invalid source address")
		}
		dst, ok := h.SourceAddr.(*net.UnixAddr)
		if !ok || dst.Net != "unixgram" || len(dst.Name) > 108 {
			return 0, errors.New("invalid destination address")
		}
		copy(addr, src.Name)
		copy(addr[108:], dst.Name)
	}
	rawHdr.Len = uint16(16 + len(addr) + len(h.Trailing))

	err := binary.Write(w, binary.BigEndian, rawHdr)
	if err != nil {
		return 0, err
	}

	n, err := w.Write(addr)
	if err != nil {
		return int64(16 + n), err
	}

	n, err = w.Write(h.Trailing)
	return int64(16 + len(addr) + n), err
}
