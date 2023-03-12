package proxyprotocol

import (
	"encoding/binary"
	"errors"
	"io"
)

type TLV struct {
	Type  PP2Type
	Value []byte
}

type PP2Type byte

const (
	PP2TypeALPN      PP2Type = 0x01
	PP2TypeAuthority PP2Type = 0x02
	PP2TypeCRC32C    PP2Type = 0x03
	PP2TypeNOOP      PP2Type = 0x04
	PP2TypeUniqueID  PP2Type = 0x05
	PP2TypeSSL       PP2Type = 0x20
	PP2TypeNetNS     PP2Type = 0x30

	PP2SubTypeSSLVersion PP2Type = 0x21
	PP2SubTypeSSLCN      PP2Type = 0x22
	PP2SubTypeSSLCipher  PP2Type = 0x23
	PP2SubTypeSSLSigAlg  PP2Type = 0x24
	PP2SubTypeSSLKeyAlg  PP2Type = 0x25
)

// ParseTLVs parses a slice of bytes into a slice of TLVs.
//
// No additional validation is performed on the TLVs byond the
// length field.
func ParseTLVs(b []byte) ([]TLV, error) {
	if len(b) == 0 {
		return nil, nil
	}

	var res []TLV
	for len(b) > 0 {
		if len(b) < 3 {
			return nil, io.ErrUnexpectedEOF
		}
		value := make([]byte, int(binary.BigEndian.Uint16(b[1:])))
		if len(b) < 3+len(value) {
			return nil, io.ErrUnexpectedEOF
		}
		copy(value, b[3:])
		res = append(res, TLV{
			Type:  PP2Type(b[0]),
			Value: value,
		})
		b = b[3+len(value):]
	}

	return res, nil
}

func (t TLV) WriteTo(w io.Writer) (int64, error) {
	if len(t.Value) > 0xffff {
		return 0, errors.New("TLV value too long")
	}

	var hdr [3]byte
	hdr[0] = byte(t.Type)
	binary.BigEndian.PutUint16(hdr[1:], uint16(len(t.Value)))

	n, err := w.Write(hdr[:])
	if err != nil {
		return int64(n), err
	}

	n, err = w.Write(t.Value)
	return int64(3 + n), err
}

// FindTLV is a convenience function to find the first value of a TLV
// in a Header.
func FindTLV(h Header, t PP2Type) (value []byte, has bool) {
	var tlvs []TLV
	switch h := h.(type) {
	case HeaderV2:
		tlvs = h.TLVs
	case *HeaderV2:
		tlvs = h.TLVs
	default:
		return nil, false
	}

	for _, tlv := range tlvs {
		if tlv.Type != t {
			continue
		}

		return tlv.Value, true
	}

	return nil, false
}
