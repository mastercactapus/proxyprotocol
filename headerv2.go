package proxyprotocol

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// HeaderV2 contains information relayed by the PROXY protocol version 2 (binary) header.
type HeaderV2 struct {
	Command    Command
	Family     AddrFamily
	Protocol   Proto
	SourceAddr net.Addr
	DestAddr   net.Addr
	Trailing   []byte
}

type rawV2 struct {
	Sig      [12]byte
	VerCmd   byte
	FamProto byte
	Len      uint16
}

func parseV2(r *bufio.Reader) (Header, error) {
	buf := make([]byte, 232)
	n, err := io.ReadFull(r, buf[:16])
	if err != nil {
		return nil, &InvalidHeaderErr{Read: buf[:n], error: err}
	}
	var rawHdr rawV2
	err = binary.Read(bytes.NewReader(buf), binary.BigEndian, &rawHdr)
	if err != nil {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: err}
	}
	if !bytes.Equal(rawHdr.Sig[:], sigV2) {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid signature")}
	}
	// highest 4 indicate version
	if (rawHdr.VerCmd >> 4) != 2 {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 version value")}
	}
	var h HeaderV2
	// lowest 4 = command (0xf == 0b00001111)
	h.Command = Command(rawHdr.VerCmd & 0xf)
	if h.Command > CommandProxy {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 command")}
	}

	// highest 4 indicate address family
	h.Family = AddrFamily(rawHdr.FamProto >> 4)
	if h.Family > AddrFamilyUnix {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 address family")}
	}

	// lowest 4 = transport protocol (0xf == 0b00001111)
	h.Protocol = Proto(rawHdr.FamProto & 0xf)
	if h.Protocol > ProtoDGram {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 transport protocol")}
	}

	fmt.Println("LEN", len(buf), rawHdr.Len)
	if 16+int(rawHdr.Len) > len(buf) {
		newBuf := make([]byte, 16+int(rawHdr.Len))
		copy(newBuf, buf[:16])
		buf = newBuf
	} else {
		buf = buf[:16+int(rawHdr.Len)]
	}

	n, err = io.ReadFull(r, buf[16:])
	if err != nil {
		return nil, &InvalidHeaderErr{Read: buf[:16+n], error: err}
	}

	var addrLen int
	switch rawHdr.FamProto {
	case 0x11: // TCP over IPv4
		addrLen = 12
		h.SourceAddr = &net.TCPAddr{
			IP:   net.IP(buf[16:20]),
			Port: int(binary.BigEndian.Uint16(buf[24:])),
		}
		h.DestAddr = &net.TCPAddr{
			IP:   net.IP(buf[20:24]),
			Port: int(binary.BigEndian.Uint16(buf[26:])),
		}
	case 0x12: // UDP over IPv4
		addrLen = 12
		h.SourceAddr = &net.UDPAddr{
			IP:   net.IP(buf[16:20]),
			Port: int(binary.BigEndian.Uint16(buf[24:])),
		}
		h.DestAddr = &net.UDPAddr{
			IP:   net.IP(buf[20:24]),
			Port: int(binary.BigEndian.Uint16(buf[26:])),
		}
	case 0x21: // TCP over IPv6
		addrLen = 36
		h.SourceAddr = &net.TCPAddr{
			IP:   net.IP(buf[16:32]),
			Port: int(binary.BigEndian.Uint16(buf[48:])),
		}
		h.DestAddr = &net.TCPAddr{
			IP:   net.IP(buf[32:48]),
			Port: int(binary.BigEndian.Uint16(buf[50:])),
		}
	case 0x22: // UDP over IPv6
		addrLen = 36
		h.SourceAddr = &net.UDPAddr{
			IP:   net.IP(buf[16:32]),
			Port: int(binary.BigEndian.Uint16(buf[48:])),
		}
		h.DestAddr = &net.UDPAddr{
			IP:   net.IP(buf[32:48]),
			Port: int(binary.BigEndian.Uint16(buf[50:])),
		}
	case 0x31: // UNIX stream
		addrLen = 216
		h.SourceAddr = &net.UnixAddr{
			Net:  "unix",
			Name: strings.TrimRight(string(buf[16:124]), "\x00"),
		}
		h.DestAddr = &net.UnixAddr{
			Net:  "unix",
			Name: strings.TrimRight(string(buf[124:232]), "\x00"),
		}
	case 0x32: // UNIX datagram
		addrLen = 216
		h.SourceAddr = &net.UnixAddr{
			Net:  "unixgram",
			Name: strings.TrimRight(string(buf[16:124]), "\x00"),
		}
		h.DestAddr = &net.UnixAddr{
			Net:  "unixgram",
			Name: strings.TrimRight(string(buf[124:232]), "\x00"),
		}
	}
	h.Trailing = buf[16+addrLen:]
	return h, nil
}

// FromConn will populate header data from the given net.Conn.
// It is assumed the connection is incomming, and the header is set to proxy
// details forward.
//
// Specifically, the RemoteAddr of the Conn will be considered the Source address/port
// and the LocalAddr of the Conn will be considered the Destination address/port for
// the purposes of the PROXY header.
func (h *HeaderV2) FromConn(c net.Conn) error {
	h.Command = CommandProxy
	switch t := c.LocalAddr().(type) {
	case *net.TCPAddr:
		h.Protocol = ProtoStream
		if t.IP.To4() != nil {
			h.Family = AddrFamilyInet
		} else {
			h.Family = AddrFamilyInet6
		}
	case *net.UDPAddr:
		h.Protocol = ProtoDGram
		if t.IP.To4() != nil {
			h.Family = AddrFamilyInet
		} else {
			h.Family = AddrFamilyInet6
		}
	case *net.UnixAddr:
		h.Family = AddrFamilyUnix
		switch t.Net {
		case "unix":
			h.Protocol = ProtoStream
		case "unixgram":
			h.Protocol = ProtoDGram
		default:
			return errors.New("unknown unix net")
		}
	}
	h.SourceAddr = c.RemoteAddr()
	h.DestAddr = c.LocalAddr()
	return nil
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
