package tlsvector

type Version uint16

func (mv Version) Raw() uint16 {
	return uint16(mv)
}

func (mv Version) Lo() uint8 {
	return uint8(mv >> 8)
}

func (mv Version) Hi() uint8 {
	return uint8(mv)
}

func (mv Version) Short() string {
	switch {
	case mv == 0x0300:
		return "30"
	case mv == 0x0301:
		return "10"
	case mv == 0x0302:
		return "11"
	case mv == 0x0303:
		return "12"
	case mv == 0x0304:
		return "13"
	case mv == 0xfeff:
		return "10"
	case mv == 0xfefd:
		return "12"
	case mv == 0xfefc:
		return "13"
	default:
		return "00"
	}
}

func (mv Version) String() string {
	switch {
	case mv == 0x0300:
		return "SSL3.0"
	case mv == 0x0301:
		return "TLS1.0"
	case mv == 0x0302:
		return "TLS1.1"
	case mv == 0x0303:
		return "TLS1.2"
	case mv == 0x0304:
		return "TLS1.3"
	case mv == 0xfeff:
		return "DTLS1.0"
	case mv == 0xfefd:
		return "DTLS1.2"
	case mv == 0xfefc:
		return "DTLS1.3"
	default:
		return "UNK"
	}
}
