package tlsvector

import (
	"encoding/binary"
)

func (vec *vector) parseTLSVersion(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 2); err != nil {
		return off, err
	}
	vec.mver = Version(binary.BigEndian.Uint16(raw))
	return off, err
}
