package tlsvector

import "github.com/koykov/byteconv"

func (vec *vector) Parse(raw []byte) (err error) {
	vec.Reset()
	vec.raw = raw
	var off uint32

	if off, err = vec.parseRecordHeader(off); err != nil {
		return
	}
	if off, err = vec.parseHandshakeHeader(off); err != nil {
		return
	}
	if off, err = vec.parseHandshakeReconstructionData(off); err != nil {
		return
	}
	if off, err = vec.parseTLSVersion(off); err != nil {
		return
	}
	if off, err = vec.parseClientRandom(off); err != nil {
		return err
	}
	if off, err = vec.parseSessionID(off); err != nil {
		return
	}
	if off, err = vec.parseCookie(off); err != nil {
		return
	}
	switch vec.mtyp {
	case MessageTypeClientHello:
		if off, err = vec.parseCipherSuites(off); err != nil {
			return
		}
		if off, err = vec.parseCompressionMethods(off); err != nil {
			return
		}
	case MessageTypeServerHello:
		if off, err = vec.parseCipherSuite(off); err != nil {
			return
		}
		if off, err = vec.parseCompressionMethod(off); err != nil {
			return
		}
	}
	if off, err = vec.parseExtensions(off); err != nil {
		return
	}
	return
}

func (vec *vector) ParseString(raw string) error {
	return vec.Parse(byteconv.S2B(raw))
}
