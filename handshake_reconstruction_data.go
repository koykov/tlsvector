package tlsvector

import "encoding/binary"

func (vec *vector) parseHandshakeReconstructionData(off uint32) (_ uint32, err error) {
	if vec.rver.Hi() < 0x03 {
		// Non DTLS.
		return off, nil
	}
	var raw []byte
	if raw, off, err = vec.cut(off, 8); err != nil {
		return off, err
	}
	// Read message sequence number.
	vec.mseq = binary.BigEndian.Uint16(raw[0:2])
	// Read fragment offset.
	vec.frgo = uint32(raw[4]) | uint32(raw[3])<<8 | uint32(raw[2])<<16
	// Read fragment length.
	vec.frgo = uint32(raw[7]) | uint32(raw[6])<<8 | uint32(raw[5])<<16

	return off, err
}
