package tlsvector

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"

	"github.com/koykov/byteconv"
)

type Interface interface {
	fmt.Stringer
	Parse(p []byte) error
	ParseString(s string) error
	Reset()

	RecordType() RecordType
	RecordLegacyVersion() Version
	KeyEpoch() uint16 // DTLS
	RecordLength() uint16

	MessageType() MessageType
	MessageLength() uint32
	MessageSequenceNumber() uint16 // DTLS
	FragmentOffset() uint32        // DTLS
	FragmentLength() uint32        // DTLS
	LegacyVersion() Version
	Random() []byte
	SessionID() []byte
	CipherSuites() []CipherSuite
	CompressionMethod() uint8
	Extensions() []Extension
	Version() Version

	AppendDescription(dst []byte) []byte

	JSON() string
	AppendJSON(dst []byte) []byte

	JA3() []byte
	AppendJA3(dst []byte) []byte
	JA3String() []byte
	AppendJA3String(dst []byte) []byte

	JA4() []byte
	AppendJA4(dst []byte) []byte
	JA4String() []byte
	AppendJA4String(dst []byte) []byte
}

type vector struct {
	raw   []byte
	buf   []byte
	buf16 []uint16
	svext int

	rtyp RecordType // record type (always handshake)
	rver Version    // record version (legacy)
	keph uint16     // key epoch (DTLS only)
	rseq uint64     // sequence number (DTLS only)
	rlen uint16     // record length (including handshake header)

	mtyp MessageType   // message type
	mlen uint32        // message length
	mseq uint16        // message sequence number (DTLS only)
	frgo uint32        // fragment offset (DTLS only)
	frgl uint32        // fragment length (DTLS only)
	mver Version       // TLS version (legacy)
	rand uint64        // client random
	sid  uint64        // session ID
	chps []CipherSuite // cipher suites
	cmpl uint8         // compression method
	cmps uint8         // compression method
	ext  []Extension   // extensions

	ja3, ja4 hash.Hash
}

func New() Interface {
	return &vector{}
}

func (vec *vector) RecordType() RecordType {
	return vec.rtyp
}

func (vec *vector) RecordLegacyVersion() Version {
	return vec.rver
}

func (vec *vector) KeyEpoch() uint16 {
	return vec.keph
}

func (vec *vector) RecordLength() uint16 {
	return vec.rlen
}

func (vec *vector) MessageType() MessageType {
	return vec.mtyp
}

func (vec *vector) MessageLength() uint32 {
	return vec.mlen
}

func (vec *vector) MessageSequenceNumber() uint16 {
	return vec.mseq
}

func (vec *vector) FragmentOffset() uint32 {
	return vec.frgo
}

func (vec *vector) FragmentLength() uint32 {
	return vec.frgl
}

func (vec *vector) LegacyVersion() Version {
	return vec.mver
}

func (vec *vector) Random() []byte {
	lo, hi := uint32(vec.rand>>32), uint32(vec.rand)
	return vec.raw[lo:hi]
}

func (vec *vector) SessionID() []byte {
	lo, hi := uint32(vec.sid>>32), uint32(vec.sid)
	return vec.raw[lo:hi]
}

func (vec *vector) CipherSuites() []CipherSuite {
	return vec.chps
}

func (vec *vector) CompressionMethod() uint8 {
	return vec.cmps
}

func (vec *vector) Extensions() []Extension {
	return vec.ext
}

func (vec *vector) Version() Version {
	// Look for "supported_versions" extension first.
	if vec.svext >= 0 && vec.svext < len(vec.ext) {
		var mx Version
		ext := NewExtensionSupportedVersions(vec.ext[vec.svext].Data.Bytes())
		ext.Each(func(version Version) {
			if isGREASE(version.Raw()) {
				return
			}
			if version.Raw() > mx.Raw() {
				mx = version
			}
		})
		if mx.Raw() > 0 {
			return mx
		}
	}
	// Fallback to message version.
	return vec.mver
}

func (vec *vector) String() string {
	buf := make([]byte, 0, 5*1024)
	buf = vec.AppendDescription(buf[:0])
	return byteconv.B2S(buf)
}

func (vec *vector) AppendDescription(dst []byte) []byte {
	dst = append(dst, "Record:\n"...)

	dst = fmt.Appendf(dst, "\tType: %s (%d)\n", vec.rtyp.String(), vec.rtyp)
	dst = fmt.Appendf(dst, "\tLegacy version: %s (0x%04X)\n", vec.rver.String(), vec.rver.Raw())
	dst = fmt.Appendf(dst, "\tLength: %d\n", vec.rlen)

	dst = append(dst, "Handshake:\n"...)
	dst = fmt.Appendf(dst, "\tType: %s (0x%02X)\n", vec.mtyp.String(), vec.mtyp.Raw())
	dst = fmt.Appendf(dst, "\tLength: %d\n", vec.mlen)
	ver := vec.Version()
	dst = fmt.Appendf(dst, "\tVersion: %s (0x%04X)\n", ver.String(), ver.Raw())
	dst = fmt.Appendf(dst, "\tRandom: %X\n", vec.Random())
	sid := vec.SessionID()
	dst = fmt.Appendf(dst, "\tSession ID Length: %d\n", len(sid))
	if len(sid) > 0 {
		dst = fmt.Appendf(dst, "\tSession ID: %X\n", sid)
	} else {
		dst = append(dst, "\tSession ID: N/D\n"...)
	}

	if len(vec.chps) > 0 {
		dst = append(dst, "\tCipher Suites:\n"...)
		for i := 0; i < len(vec.chps); i++ {
			dst = fmt.Appendf(dst, "\t\t%s (0x%02X)\n", vec.chps[i].String(), vec.chps[i].Raw())
		}
	} else {
		dst = append(dst, "\tCipher Suites: N/D\n"...)
	}

	dst = fmt.Appendf(dst, "\tCompression Method Length: %d\n", vec.cmpl)
	if vec.cmps == 0 {
		dst = append(dst, "\tCompression Method: NULL (0)\n"...)
	} else {
		dst = fmt.Appendf(dst, "\tCompression Method: %02X\n", vec.cmps)
	}

	if len(vec.ext) > 0 {
		dst = append(dst, "\tExtensions:\n"...)
		for i := 0; i < len(vec.ext); i++ {
			e := &vec.ext[i]
			name := e.Type.String()
			if isGREASE(e.Type.Raw()) {
				name = "grease"
			}
			if len(name) == 0 {
				name = "unknown"
			}
			dst = fmt.Appendf(dst, "\t\t%s (0x%04X):\n", name, e.Type.Raw())
			dst = e.AppendDescription(dst, "\t\t\t")
		}
	} else {
		dst = append(dst, "\tExtensions: N/D\n"...)
	}

	return dst
}

func (vec *vector) JSON() string {
	buf := make([]byte, 0, 5*1024)
	buf = vec.AppendJSON(buf[:0])
	return byteconv.B2S(buf)
}

func (vec *vector) AppendJSON(dst []byte) []byte {
	dst = append(dst, '{')
	dst = append(dst, `"record":{`...)
	dst = append(dst, `"type":"`...)
	dst = append(dst, vec.rtyp.String()...)
	dst = append(dst, `",`...)
	dst = append(dst, `"type_raw":`...)
	dst = strconv.AppendUint(dst, uint64(vec.rtyp), 10)
	ver := vec.Version()
	dst = append(dst, `,"version":"`...)
	dst = append(dst, ver.String()...)
	dst = append(dst, `","version_raw":`...)
	dst = strconv.AppendUint(dst, uint64(ver.Raw()), 10)
	dst = append(dst, `,"length":`...)
	dst = strconv.AppendUint(dst, uint64(vec.rlen), 10)

	dst = append(dst, `},"handshake":{`...)
	dst = append(dst, `"type":"`...)
	dst = append(dst, vec.mtyp.String()...)
	dst = append(dst, `",`...)
	dst = append(dst, `"type_raw":`...)
	dst = strconv.AppendUint(dst, uint64(vec.mtyp.Raw()), 10)
	dst = append(dst, `,"legacy_version":"`...)
	dst = append(dst, vec.mver.String()...)
	dst = append(dst, `","legacy_version_raw":`...)
	dst = strconv.AppendUint(dst, uint64(vec.mver.Raw()), 10)
	dst = append(dst, `,"random":"`...)
	dst = hex.AppendEncode(dst, vec.Random())
	dst = append(dst, `","session_id_length":`...)
	sid := vec.SessionID()
	dst = strconv.AppendUint(dst, uint64(len(sid)), 10)
	dst = append(dst, ',')
	if len(sid) > 0 {
		dst = append(dst, `"session_id":"`...)
		dst = hex.AppendEncode(dst, sid)
		dst = append(dst, `",`...)
	}
	if len(vec.chps) > 0 {
		dst = append(dst, `"cipher_suites":[`...)
		for i := 0; i < len(vec.chps); i++ {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = append(dst, `{"name":"`...)
			dst = append(dst, vec.chps[i].String()...)
			dst = append(dst, `","value":`...)
			dst = strconv.AppendUint(dst, uint64(vec.chps[i].Raw()), 10)
			dst = append(dst, `}`...)
		}
		dst = append(dst, `],`...)
	}

	dst = append(dst, `"compression_method_length":`...)
	dst = strconv.AppendUint(dst, uint64(vec.cmpl), 10)
	if vec.cmpl > 0 {
		dst = append(dst, `,"compression_method":`...)
		dst = strconv.AppendUint(dst, uint64(vec.cmps), 10)
	}

	if len(vec.ext) > 0 {
		dst = append(dst, `,"extensions":[`...)
		for i := 0; i < len(vec.ext); i++ {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = append(dst, `{"name":"`...)
			e := &vec.ext[i]
			name := e.Type.String()
			if isGREASE(e.Type.Raw()) {
				name = "grease"
			}
			if len(name) == 0 {
				name = "unknown"
			}
			pos := strings.IndexByte(name, '"')
			if pos == -1 {
				dst = append(dst, name...)
			} else {
				for {
					dst = append(dst, name[:pos]...)
					dst = append(dst, '\\')
					dst = append(dst, '"')
					name = name[pos+1:]
					pos = strings.IndexByte(name, '"')
					if pos == -1 {
						dst = append(dst, name...)
						break
					}
				}
			}
			dst = append(dst, `","type":`...)
			dst = strconv.AppendUint(dst, uint64(e.Type.Raw()), 10)
			dst = append(dst, `,`...)
			dst = append(dst, `"payload":{`...)
			dst = e.AppendJSON(dst)
			dst = append(dst, '}')
			dst = append(dst, '}')
		}
		dst = append(dst, ']')
	}
	dst = append(dst, '}')
	dst = append(dst, '}')

	return dst
}

func (vec *vector) Reset() {
	vec.raw = vec.raw[:0]
	vec.resetBuf()
	vec.svext = -1

	vec.rtyp = RecordTypeUnknown
	vec.rver = 0
	vec.keph = 0
	vec.rseq = 0
	vec.rlen = 0

	vec.mtyp = MessageTypeUnknown
	vec.mlen = 0
	vec.mseq = 0
	vec.frgo = 0
	vec.frgl = 0
	vec.mver = 0
	vec.rand = 0
	vec.sid = 0
	vec.chps = vec.chps[:0]
	vec.cmpl = 0
	vec.cmps = 0
	vec.ext = vec.ext[:0]

	if vec.ja3 != nil {
		vec.ja3.Reset()
	}
	if vec.ja4 != nil {
		vec.ja4.Reset()
	}
}

func (vec *vector) resetBuf() {
	vec.buf = vec.buf[:0]
	vec.buf16 = vec.buf16[:0]
}

func (vec *vector) cut(off, delta uint32) ([]byte, uint32, error) {
	if uint32(len(vec.raw)) < off+delta {
		return nil, off, io.ErrUnexpectedEOF
	}
	return vec.raw[off : off+delta], off + delta, nil
}
