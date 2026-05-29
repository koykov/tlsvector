package tlsvector

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"

	"github.com/koykov/byteconv"
)

func (vec *vector) JA4() string {
	raw, cs, ex := vec.ja4s()
	cslo, cshi := uint16(cs>>16), uint16(cs)
	exlo, exhi := uint16(ex>>16), uint16(ex)
	if vec.ja4 == nil {
		vec.ja4 = sha256.New()
	}
	off := len(vec.buf)
	vec.buf = append(vec.buf, "00000000000000000000000000000000"...)
	hbuf := vec.buf[off : off+32]

	vec.ja4.Write(raw[cslo:cshi])
	hbuf = vec.ja4.Sum(hbuf[:0])
	vec.buf = hex.AppendEncode(vec.buf, hbuf)
	copy(raw[cslo:cslo+12], vec.buf[off+32:off+32+12])
	raw[cslo+12] = '_'

	vec.buf = vec.buf[:off+32]
	vec.ja4.Reset()
	vec.ja4.Write(raw[exlo:exhi])
	hbuf = vec.ja4.Sum(hbuf[:0])
	vec.buf = hex.AppendEncode(vec.buf, hbuf)
	copy(raw[cslo+13:cslo+13+12], vec.buf[off+32:off+32+12])
	raw = raw[:cslo+13+12]

	return byteconv.B2S(raw)
}

func (vec *vector) JA4String() string {
	raw, _, _ := vec.ja4s()
	return byteconv.B2S(raw)
}

func (vec *vector) ja4s() ([]byte, uint32, uint32) {
	off := len(vec.buf)

	// meta part

	vec.buf = append(vec.buf, 't')

	var ver = vec.mver
	var sni byte = 'i'
	for i := 0; i < len(vec.ext); i++ {
		ext := &vec.ext[i]
		if ext.Type == 0x002b && ext.Data.Len() > 1 {
			data := ext.Data.Bytes()[1:]
			for j := 0; j < len(data); j += 2 {
				if data[j] == 0x03 {
					ver = Version(uint16(data[j])<<8 | uint16(data[j+1]))
					break
				}
			}
			break
		}
		if ext.Type == 0x0000 && ext.Data.Len() > 0 {
			sni = 'd'
		}
	}
	vec.buf = append(vec.buf, ver.Short()...)
	vec.buf = append(vec.buf, sni)

	var chlen int
	for i := 0; i < len(vec.chps); i++ {
		cs := vec.chps[i]
		if isGREASE(cs.Raw()) {
			continue
		}
		chlen++
	}
	if chlen < 10 {
		vec.buf = append(vec.buf, '0')
	}
	vec.buf = strconv.AppendInt(vec.buf, int64(chlen), 10)

	var extlen int
	var alpn = [2]byte{'0', '0'}
	for i := 0; i < len(vec.ext); i++ {
		ext := vec.ext[i]
		if isGREASE(ext.Type.Raw()) {
			continue
		}
		if ext.Type == 0x0010 {
			ealpn := NewExtensionApplicationLayerProtocolNegotiation(ext.Data.Bytes())
			var ok bool
			ealpn.Each(func(protocol []byte) {
				if len(protocol) >= 2 && !ok {
					ok = true
					alpn[0], alpn[1] = protocol[0], protocol[len(protocol)-1]
				}
			})
		}
		extlen++
	}
	if extlen < 10 {
		vec.buf = append(vec.buf, '0')
	}
	vec.buf = strconv.AppendInt(vec.buf, int64(extlen), 10)
	vec.buf = append(vec.buf, alpn[:]...)

	// cipher suites part
	vec.buf16 = vec.buf16[:0]
	for i := 0; i < len(vec.chps); i++ {
		cs := vec.chps[i].Raw()
		if isGREASE(cs) {
			continue
		}
		vec.buf16 = append(vec.buf16, cs)
	}
	slices.Sort(vec.buf16)
	vec.buf = append(vec.buf, '_')
	var cslo, cshi uint16
	cslo = uint16(len(vec.buf) - off)
	for i := 0; i < len(vec.buf16); i++ {
		if i > 0 {
			vec.buf = append(vec.buf, ',')
		}
		vec.buf = appendHexU16(vec.buf, vec.buf16[i])
	}
	cshi = uint16(len(vec.buf) - off)

	// extensions part
	var sig *Extension
	vec.buf16 = vec.buf16[:0]
	for i := 0; i < len(vec.ext); i++ {
		et := vec.ext[i].Type.Raw()
		if isGREASE(et) || et == 0x0000 || et == 0x0010 {
			continue
		}
		if et == 0x000d {
			sig = &vec.ext[i]
		}
		vec.buf16 = append(vec.buf16, et)
	}
	slices.Sort(vec.buf16)
	vec.buf = append(vec.buf, '_')
	var exlo, exhi uint16
	exlo = uint16(len(vec.buf) - off)
	for i := 0; i < len(vec.buf16); i++ {
		if i > 0 {
			vec.buf = append(vec.buf, ',')
		}
		vec.buf = appendHexU16(vec.buf, vec.buf16[i])
	}

	// signature algorithms part
	if sig != nil {
		vec.buf = append(vec.buf, '_')
		ext := NewExtensionSignatureAlgorithms(sig.Data.Bytes())
		var buf [2]byte
		var c int
		ext.Each(func(hash byte, sa SignatureAlgorithm) {
			if c > 0 {
				vec.buf = append(vec.buf, ',')
			}
			buf[0] = hash
			buf[1] = sa.Raw()
			vec.buf = appendHexB2(vec.buf, buf)
			c++
		})
	}
	exhi = uint16(len(vec.buf) - off)

	return vec.buf[off:], uint32(cslo)<<16 | uint32(cshi), uint32(exlo)<<16 | uint32(exhi)
}
