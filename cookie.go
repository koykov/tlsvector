package tlsvector

func (vec *vector) parseCookie(off uint32) (_ uint32, err error) {
	if vec.rver.Hi() != 0xfe {
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
	// todo parse cookies
	return off, nil
}
