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
	lo, hi := byte(mv), byte(mv>>8)
	switch {
	case hi == 0x03 && lo == 0x00:
		return "30"
	case hi == 0x03 && lo == 0x01:
		return "10"
	case hi == 0x03 && lo == 0x02:
		return "11"
	case hi == 0x03 && lo == 0x03:
		return "12"
	case hi == 0x03 && lo == 0x04:
		return "13"
	default:
		return "00"
	}
}

func (mv Version) String() string {
	lo, hi := byte(mv), byte(mv>>8)
	switch {
	case hi == 0x03 && lo == 0x00:
		return "SSL3.0"
	case hi == 0x03 && lo == 0x01:
		return "TLS1.0"
	case hi == 0x03 && lo == 0x02:
		return "TLS1.1"
	case hi == 0x03 && lo == 0x03:
		return "TLS1.2"
	case hi == 0x03 && lo == 0x04:
		return "TLS1.3"
	case hi == 0xfe && lo == 0xff:
		return "DTLS1.0"
	case hi == 0xfe && lo == 0xfd:
		return "DTLS1.2"
	case hi == 0xfe && lo == 0xfc:
		return "DTLS1.3"
	default:
		return "UNK"
	}
}
