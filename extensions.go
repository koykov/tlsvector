package tlsvector

import (
	"encoding/binary"

	"github.com/koykov/byteconv"
	"github.com/koykov/byteptr"
)

type ExtensionType uint16

func (et ExtensionType) Raw() uint16 {
	return uint16(et)
}

func (et ExtensionType) String() string {
	enc := __ext[et]
	lo, hi := uint16(enc>>16), uint16(enc)
	return byteconv.B2S(__ext_buf[lo:hi])
}

type ExtensionDescriptor interface {
	AppendDescription(dst []byte, pad string) []byte
	AppendJSON(dst []byte) []byte
}

type Extension struct {
	Type ExtensionType
	Data byteptr.Byteptr
}

func (e *Extension) AppendDescription(dst []byte, pad string) []byte {
	descrFn, ok := __ext_descr[e.Type]
	if !ok {
		dst = append(dst, pad...)
		dst = append(dst, "N/D"...)
		dst = append(dst, '\n')
		return dst
	}
	e.Data.Bytes()
	descr := descrFn(e.Data.Bytes())
	return descr.AppendDescription(dst, pad)
}

func (e *Extension) AppendJSON(dst []byte) []byte {
	descrFn, ok := __ext_descr[e.Type]
	if !ok {
		return dst
	}
	e.Data.Bytes()
	descr := descrFn(e.Data.Bytes())
	dst = descr.AppendJSON(dst)
	return dst
}

func (vec *vector) parseExtensions(off uint32) (_ uint32, err error) {
	var raw []byte
	if raw, off, err = vec.cut(off, 2); err != nil {
		return off, err
	}
	ln := binary.BigEndian.Uint16(raw)
	for i := uint16(0); i < ln; {
		if raw, off, err = vec.cut(off, 4); err != nil {
			return off, err
		}
		i += 4
		var e Extension
		e.Type = ExtensionType(binary.BigEndian.Uint16(raw[0:2]))
		eln := binary.BigEndian.Uint16(raw[2:4])
		e.Data.Init(vec.raw, int(off), int(eln))
		off += uint32(eln)
		vec.ext = append(vec.ext, e)
		i += eln

		if e.Type.Raw() == 0x002B {
			vec.svext = len(vec.ext) - 1
		}
	}

	return off, nil
}
