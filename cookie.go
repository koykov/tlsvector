package tlsvector

func (vec *vector) parseCookie(off uint32) (_ uint32, err error) {
	if vec.rver.Hi() != 0xfe || vec.mtyp == MessageTypeServerHello {
		// Non DTLS.
		return off, nil
	}
	var raw []byte
	if raw, off, err = vec.cut(off, 1); err != nil {
		return off, err
	}
	if raw[0] == 0 {
		return off, err
	}
	vec.cook.Init(vec.raw, int(off), int(uint32(raw[0])))
	off += uint32(raw[0])
	return off, nil
}
