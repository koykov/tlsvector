package tlsvector

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"

	"github.com/koykov/byteconv"
)

func (vec *vector) JA3String() string {
	switch vec.mtyp {
	case MessageTypeClientHello:
		return byteconv.B2S(vec.ja3c())
	case MessageTypeServerHello:
		return byteconv.B2S(vec.ja3s())
	}
	return ""
}

func (vec *vector) JA3() string {
	var bin []byte
	switch vec.mtyp {
	case MessageTypeClientHello:
		bin = vec.ja3c()
	case MessageTypeServerHello:
		bin = vec.ja3s()
	default:
		return ""
	}

	if vec.ja3 == nil {
		vec.ja3 = md5.New()
	}
	vec.ja3.Reset()
	vec.ja3.Write(bin)
	off := len(vec.buf)
	vec.buf = append(vec.buf, "0000000000000000"...)
	h := vec.ja3.Sum(vec.buf[off:off])

	off = len(vec.buf)
	vec.buf = append(vec.buf, "00000000000000000000000000000000"...)
	hex.Encode(vec.buf[off:off+32], h)

	return byteconv.B2S(vec.buf[off:])
}

func (vec *vector) ja3c() []byte {
	off := len(vec.buf)
	vec.buf = strconv.AppendUint(vec.buf, uint64(vec.mver.Raw()), 10)
	vec.buf = append(vec.buf, ',')

	if len(vec.chps) > 0 {
		var c int
		for i := 0; i < len(vec.chps); i++ {
			cs := vec.chps[i]
			if isGREASE(cs.Raw()) {
				continue
			}
			if c > 0 {
				vec.buf = append(vec.buf, '-')
			}
			vec.buf = strconv.AppendUint(vec.buf, uint64(cs.Raw()), 10)
			c++
		}
		vec.buf = append(vec.buf, ',')
	}

	ec, ecpf := -1, -1
	if len(vec.ext) > 0 {
		var c int
		for i := 0; i < len(vec.ext); i++ {
			ext := vec.ext[i]
			if isGREASE(ext.Type.Raw()) {
				continue
			}
			if c > 0 {
				vec.buf = append(vec.buf, '-')
			}
			vec.buf = strconv.AppendUint(vec.buf, uint64(ext.Type.Raw()), 10)
			if ext.Type.Raw() == 0x000a {
				ec = i
			}
			if ext.Type.Raw() == 0x000b {
				ecpf = i
			}
			c++
		}
		vec.buf = append(vec.buf, ',')
	}

	if ec >= 0 {
		var c int
		ext := NewExtensionSupportedGroups(vec.ext[ec].Data.Bytes())
		ext.Each(func(group EllipticCurve) {
			if isGREASE(group.Raw()) {
				return
			}
			if c > 0 {
				vec.buf = append(vec.buf, '-')
			}
			vec.buf = strconv.AppendUint(vec.buf, uint64(group.Raw()), 10)
			c++
		})
		if c > 0 {
			vec.buf = append(vec.buf, ',')
		}
	}

	if ecpf >= 0 {
		var c int
		ext := NewExtensionECPointFormats(vec.ext[ecpf].Data.Bytes())
		ext.Each(func(format ECPointFormats) {
			if c > 0 {
				vec.buf = append(vec.buf, '-')
			}
			vec.buf = strconv.AppendUint(vec.buf, uint64(format.Raw()), 10)
			c++
		})
		if c > 0 {
			vec.buf = append(vec.buf, ',')
		}
	}

	bin := vec.buf[off : len(vec.buf)-1]
	return bin
}

func (vec *vector) ja3s() []byte {
	off := len(vec.buf)
	vec.buf = strconv.AppendUint(vec.buf, uint64(vec.mver.Raw()), 10)
	vec.buf = append(vec.buf, ',')

	if len(vec.chps) > 0 {
		var c int
		for i := 0; i < len(vec.chps); i++ {
			cs := vec.chps[i]
			if isGREASE(cs.Raw()) {
				continue
			}
			if c > 0 {
				vec.buf = append(vec.buf, '-')
			}
			vec.buf = strconv.AppendUint(vec.buf, uint64(cs.Raw()), 10)
			c++
		}
		vec.buf = append(vec.buf, ',')
	}

	if len(vec.ext) > 0 {
		var c int
		for i := 0; i < len(vec.ext); i++ {
			ext := vec.ext[i]
			if isGREASE(ext.Type.Raw()) {
				continue
			}
			if c > 0 {
				vec.buf = append(vec.buf, '-')
			}
			vec.buf = strconv.AppendUint(vec.buf, uint64(ext.Type.Raw()), 10)
			c++
		}
		vec.buf = append(vec.buf, ',')
	}

	bin := vec.buf[off : len(vec.buf)-1]
	return bin
}

// Check value is a GREASE (Generate Random Extensions And Sustain Extensibility) value.
func isGREASE(value uint16) bool {
	return (value&0x0F0F) == 0x0A0A && (value>>8) == (value&0x00FF)
}
