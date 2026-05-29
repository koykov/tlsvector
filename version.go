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
	case hi == 3 && lo == 0:
		return "30"
	case hi == 3 && lo == 1:
		return "10"
	case hi == 3 && lo == 2:
		return "11"
	case hi == 3 && lo == 3:
		return "12"
	case hi == 3 && lo == 4:
		return "13"
	default:
		return "00"
	}
}

func (mv Version) String() string {
	lo, hi := byte(mv), byte(mv>>8)
	switch {
	case hi == 3 && lo == 0:
		return "SSL3.0"
	case hi == 3 && lo == 1:
		return "TLS1.0"
	case hi == 3 && lo == 2:
		return "TLS1.1"
	case hi == 3 && lo == 3:
		return "TLS1.2"
	case hi == 3 && lo == 4:
		return "TLS1.3"
	default:
		return "UNK"
	}
}
