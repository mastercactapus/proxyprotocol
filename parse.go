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

var (
	sigV1 = []byte("PROXY %s %s %s %d %d\r\n")
	sigV2 = []byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A")
)

// InvalidHeaderErr contains the parsing error as well as all data read from the reader.
type InvalidHeaderErr struct {
	error
	Read []byte
}

// Parse will parse detect and return a V1 or V2 header, otherwise InvalidHeaderErr is returned.
func Parse(r *bufio.Reader) (Header, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	r.UnreadByte()

	switch b {
	case sigV1[0]:
		return parseV1(r)
	case sigV2[0]:
		return parseV2(r)
	}

	return nil, &InvalidHeaderErr{error: errors.New("invalid signature")}
}

func parseV1(r *bufio.Reader) (Header, error) {
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
	var fam, srcIPStr, dstIPStr string
	var srcPort, dstPort int
	n, err := fmt.Sscanf(string(buf), string(sigV1), &fam, &srcIPStr, &dstIPStr, &srcPort, &dstPort)
	if n == 0 && err != nil {
		return nil, &InvalidHeaderErr{Read: buf, error: err}
	}
	switch fam {
	case "UNKNOWN":
		return &HeaderV1{Family: fam}, nil
	case "TCP4", "TCP6":
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
	h.Family = AF(rawHdr.FamProto >> 4)
	if h.Family > AFUnix {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 address family")}
	}

	// lowest 4 = transport protocol (0xf == 0b00001111)
	h.Protocol = Proto(rawHdr.FamProto & 0xf)
	if h.Protocol > ProtoDGram {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 transport protocol")}
	}

	if int(rawHdr.Len) > len(buf) {
		newBuf := make([]byte, 16+int(rawHdr.Len))
		copy(newBuf, buf)
		buf = newBuf
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
