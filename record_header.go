package tlsvector

import (
	"encoding/binary"
	"math"
)

type RecordType uint8

const (
	RecordTypeUnknown   RecordType = 0
	RecordTypeHandshake RecordType = 0x16
)

func (rt RecordType) String() string {
	return rtyps[rt]
}

func (vec *vector) parseRecordHeader(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 3); err != nil {
		return off, err
	}
	if raw[0] != 0x16 {
		// Record header not found.
		vec.rtyp = RecordTypeUnknown
		return off, ErrNoHandshake
	}

	// Byte at position is 0x16 - handshake type.
	vec.rtyp = RecordTypeHandshake
	// Read protocol version.
	vec.rver = Version(binary.BigEndian.Uint16(raw[1:3]))

	if vec.rver.Hi() == 0xfe {
		// DTLS message found.
		if raw, off, err = vec.cut(off, 8); err != nil {
			return off, err
		}
		// Read key epoch.
		vec.keph = binary.BigEndian.Uint16(raw[0:2])
		// Read record sequence number.
		vec.rseq = uint64(raw[7]) | uint64(raw[6])<<8 | uint64(raw[5])<<16 | uint64(raw[4])<<24 | uint64(raw[3])<<32 | uint64(raw[2])<<40
	}

	// Read handshake length.
	if raw, off, err = vec.cut(off, 2); err != nil {
		return off, err
	}
	vec.rlen = binary.BigEndian.Uint16(raw[0:2])

	return off, err
}

var rtyps [math.MaxUint8]string

func init() {
	rtyps[RecordTypeUnknown] = "UNKNOWN"
	rtyps[RecordTypeHandshake] = "HANDSHAKE"
}
