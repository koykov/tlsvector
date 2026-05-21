package tlsvector

import (
	"fmt"
	"strconv"
)

// ExtensionServerName represents extension "server_name".
type ExtensionServerName struct {
	payload []byte
}

func NewExtensionServerName(payload []byte) *ExtensionServerName {
	return &ExtensionServerName{payload: payload}
}

func (e *ExtensionServerName) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionServerName) Each(fn func(nameType byte, name []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		nameType := e.payload[pos]
		nameLen := int(e.payload[pos+1])<<8 | int(e.payload[pos+2])
		pos += 3
		if pos+nameLen > len(e.payload) {
			break
		}
		fn(nameType, e.payload[pos:pos+nameLen])
		pos += nameLen
	}
}

func (e *ExtensionServerName) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(nameType byte, name []byte) {
		dst = append(dst, pad...)
		dst = append(dst, "type="...)
		dst = strconv.AppendInt(dst, int64(nameType), 10)
		dst = append(dst, " name="...)
		dst = append(dst, name...)
		dst = append(dst, '\n')
	})
	return dst
}

func (e *ExtensionServerName) AppendJSON(dst []byte) []byte {
	dst = append(dst, `"items":[`...)
	var c int
	e.Each(func(nameType byte, name []byte) {
		if c > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, `{"type":`...)
		dst = strconv.AppendInt(dst, int64(nameType), 10)
		dst = append(dst, `","name":"`...)
		dst = append(dst, name...)
		dst = append(dst, `"}`...)
		c++
	})
	dst = append(dst, ']')
	return dst
}

// ---

// ExtensionMaxFragmentLength represents extension "max_fragment_length".
type ExtensionMaxFragmentLength struct {
	payload []byte
}

func NewExtensionMaxFragmentLength(payload []byte) *ExtensionMaxFragmentLength {
	return &ExtensionMaxFragmentLength{payload: payload}
}

func (e *ExtensionMaxFragmentLength) Value() byte {
	if len(e.payload) < 1 {
		return 0
	}
	return e.payload[0]
}

func (e *ExtensionMaxFragmentLength) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = append(dst, "max_fragment_length "...)
	dst = strconv.AppendInt(dst, int64(e.Value()), 10)
	dst = append(dst, '\n')
	return dst
}

func (e *ExtensionMaxFragmentLength) AppendJSON(dst []byte) []byte {
	dst = append(dst, `"max_fragment_length":`...)
	dst = strconv.AppendInt(dst, int64(e.Value()), 10)
	return dst
}

// ---

// ExtensionClientCertificateURL represents extension "client_certificate_url".
type ExtensionClientCertificateURL struct {
	payload []byte
}

func NewExtensionClientCertificateURL(payload []byte) *ExtensionClientCertificateURL {
	return &ExtensionClientCertificateURL{payload: payload}
}

func (e *ExtensionClientCertificateURL) Length() int {
	return len(e.payload)
}

func (e *ExtensionClientCertificateURL) Each(fn func(url []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		urlLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+urlLen > len(e.payload) {
			break
		}
		fn(e.payload[pos : pos+urlLen])
		pos += urlLen
	}
}

func (e *ExtensionClientCertificateURL) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(url []byte) {
		dst = append(dst, pad...)
		dst = append(dst, url...)
		dst = append(dst, '\n')
	})
	return dst
}

func (e *ExtensionClientCertificateURL) AppendJSON(dst []byte) []byte {
	dst = append(dst, `"urls":[`...)
	var c int
	e.Each(func(url []byte) {
		if c > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, '"')
		dst = append(dst, url...)
		dst = append(dst, '"')
		c++
	})
	dst = append(dst, ']')
	return dst
}

// ---

// ExtensionTrustedCAKeys represents extension "trusted_ca_keys".
type ExtensionTrustedCAKeys struct {
	payload []byte
}

func NewExtensionTrustedCAKeys(payload []byte) *ExtensionTrustedCAKeys {
	return &ExtensionTrustedCAKeys{payload: payload}
}

func (e *ExtensionTrustedCAKeys) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionTrustedCAKeys) Each(fn func(caID []byte, dnList []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		caIDLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+caIDLen > len(e.payload) {
			break
		}
		caID := e.payload[pos : pos+caIDLen]
		pos += caIDLen
		if pos+2 > len(e.payload) {
			break
		}
		dnListLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+dnListLen > len(e.payload) {
			break
		}
		dnList := e.payload[pos : pos+dnListLen]
		pos += dnListLen
		fn(caID, dnList)
	}
}

func (e *ExtensionTrustedCAKeys) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(caID []byte, dnList []byte) {
		dst = append(dst, pad...)
		dst = append(dst, "ca_id="...)
		dst = append(dst, caID...)
		dst = append(dst, " dn_list="...)
		dst = append(dst, dnList...)
		dst = append(dst, '\n')
	})
	return dst
}

func (e *ExtensionTrustedCAKeys) AppendJSON(dst []byte) []byte {
	dst = append(dst, `"keys":[`...)
	var c int
	e.Each(func(caID []byte, dnList []byte) {
		if c > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, '{')
		dst = append(dst, `"ca_id":`...)
		dst = append(dst, caID...)
		dst = append(dst, `","dn_list":"`...)
		dst = append(dst, dnList...)
		dst = append(dst, `"}`...)
		c++
	})
	dst = append(dst, ']')
	return dst
}

// ---

// ExtensionTruncatedHMAC represents extension "truncated_hmac".
type ExtensionTruncatedHMAC struct {
	payload []byte
}

func NewExtensionTruncatedHMAC(payload []byte) *ExtensionTruncatedHMAC {
	return &ExtensionTruncatedHMAC{payload: payload}
}

func (e *ExtensionTruncatedHMAC) Length() int {
	return len(e.payload)
}

func (e *ExtensionTruncatedHMAC) Each(fn func(hmacLen byte)) {
	for _, b := range e.payload {
		fn(b)
	}
}

func (e *ExtensionTruncatedHMAC) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(hmacLen byte) {
		dst = append(dst, pad...)
		dst = strconv.AppendInt(dst, int64(hmacLen), 10)
		dst = append(dst, '\n')
	})
	return dst
}

func (e *ExtensionTruncatedHMAC) AppendJSON(dst []byte) []byte {
	dst = append(dst, `"hmac":[`...)
	var c int
	e.Each(func(hmacLen byte) {
		if c > 0 {
			dst = append(dst, ',')
		}
		dst = strconv.AppendInt(dst, int64(hmacLen), 10)
		c++
	})
	dst = append(dst, ']')
	return dst
}

// ---

// ExtensionStatusRequest represents extension "status_request".
type ExtensionStatusRequest struct {
	payload []byte
}

func NewExtensionStatusRequest(payload []byte) *ExtensionStatusRequest {
	return &ExtensionStatusRequest{payload: payload}
}

func (e *ExtensionStatusRequest) StatusType() byte {
	if len(e.payload) < 1 {
		return 0
	}
	return e.payload[0]
}

func (e *ExtensionStatusRequest) ResponderIDListLength() int {
	if len(e.payload) < 3 {
		return 0
	}
	return int(e.payload[1])<<8 | int(e.payload[2])
}

func (e *ExtensionStatusRequest) Each(fn func(id []byte)) {
	if len(e.payload) < 3 {
		return
	}
	listLen := int(e.payload[1])<<8 | int(e.payload[2])
	pos := 3
	for pos < 3+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		idLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+idLen > len(e.payload) {
			break
		}
		fn(e.payload[pos : pos+idLen])
		pos += idLen
	}
}

func (e *ExtensionStatusRequest) RequestExtensionLength() int {
	if len(e.payload) < 5+int(e.ResponderIDListLength()) {
		return 0
	}
	offset := 3 + e.ResponderIDListLength()
	return int(e.payload[offset])<<8 | int(e.payload[offset+1])
}

func (e *ExtensionStatusRequest) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = append(dst, "type="...)
	dst = strconv.AppendInt(dst, int64(e.StatusType()), 10)
	dst = append(dst, '\n')
	dst = append(dst, pad...)
	dst = append(dst, "responder_ids ["...)
	dst = strconv.AppendInt(dst, int64(e.ResponderIDListLength()), 10)
	dst = append(dst, "]\n"...)
	e.Each(func(id []byte) {
		dst = append(dst, pad...)
		dst = append(dst, '\t')
		dst = append(dst, id...)
		dst = append(dst, '\n')
	})
	dst = append(dst, pad...)
	dst = append(dst, "request_ext_len="...)
	dst = strconv.AppendInt(dst, int64(e.RequestExtensionLength()), 10)
	dst = append(dst, '\n')
	return dst
}

func (e *ExtensionStatusRequest) AppendJSON(dst []byte) []byte {
	dst = append(dst, `"type":`...)
	dst = strconv.AppendInt(dst, int64(e.StatusType()), 10)
	dst = append(dst, `,"responder_ids_len":`...)
	dst = strconv.AppendInt(dst, int64(e.ResponderIDListLength()), 10)
	dst = append(dst, `,"items":[`...)
	var c int
	e.Each(func(id []byte) {
		if c > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, '"')
		dst = append(dst, id...)
		dst = append(dst, '"')
		c++
	})
	dst = append(dst, `],`...)
	dst = append(dst, `"request_ext_len":`...)
	dst = strconv.AppendInt(dst, int64(e.RequestExtensionLength()), 10)
	return dst
}

// ---

// ExtensionUserMapping represents extension "user_mapping".
type ExtensionUserMapping struct {
	payload []byte
}

func NewExtensionUserMapping(payload []byte) *ExtensionUserMapping {
	return &ExtensionUserMapping{payload: payload}
}

func (e *ExtensionUserMapping) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionUserMapping) Each(fn func(mappingType byte, data []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+1 > len(e.payload) {
			break
		}
		mappingType := e.payload[pos]
		pos++
		if pos+2 > len(e.payload) {
			break
		}
		dataLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+dataLen > len(e.payload) {
			break
		}
		fn(mappingType, e.payload[pos:pos+dataLen])
		pos += dataLen
	}
}

func (e *ExtensionUserMapping) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(mappingType byte, data []byte) {
		dst = append(dst, pad...)
		dst = append(dst, "type="...)
		dst = strconv.AppendInt(dst, int64(mappingType), 10)
		dst = append(dst, " data="...)
		dst = append(dst, data...)
		dst = append(dst, '\n')
	})
	return dst
}

func (e *ExtensionUserMapping) AppendJSON(dst []byte) []byte {
	dst = append(dst, `"items":[`...)
	var c int
	e.Each(func(mappingType byte, data []byte) {
		if c > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, '{')
		dst = append(dst, `"type":`...)
		dst = strconv.AppendInt(dst, int64(mappingType), 10)
		dst = append(dst, `,"data":"`...)
		dst = append(dst, data...)
		dst = append(dst, `"}`...)
		c++
	})
	dst = append(dst, ']')
	return dst
}

// ---

// ExtensionClientAuthz represents extension "client_authz".
type ExtensionClientAuthz struct {
	payload []byte
}

func NewExtensionClientAuthz(payload []byte) *ExtensionClientAuthz {
	return &ExtensionClientAuthz{payload: payload}
}

func (e *ExtensionClientAuthz) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionClientAuthz) Each(fn func(authzData []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		dataLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+dataLen > len(e.payload) {
			break
		}
		fn(e.payload[pos : pos+dataLen])
		pos += dataLen
	}
}

func (e *ExtensionClientAuthz) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(authzData []byte) {
		dst = append(dst, pad...)
		dst = append(dst, authzData...)
		dst = append(dst, '\n')
	})
	return dst
}

func (e *ExtensionClientAuthz) AppendJSON(dst []byte) []byte {
	dst = append(dst, `"items":[`...)
	var c int
	e.Each(func(authzData []byte) {
		if c > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, '"')
		dst = append(dst, authzData...)
		dst = append(dst, '"')
		c++
	})
	dst = append(dst, ']')
	return dst
}

// ---

// ExtensionServerAuthz represents extension "server_authz".
type ExtensionServerAuthz struct {
	payload []byte
}

func NewExtensionServerAuthz(payload []byte) *ExtensionServerAuthz {
	return &ExtensionServerAuthz{payload: payload}
}

func (e *ExtensionServerAuthz) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionServerAuthz) Each(fn func(authzData []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		dataLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+dataLen > len(e.payload) {
			break
		}
		fn(e.payload[pos : pos+dataLen])
		pos += dataLen
	}
}

func (e *ExtensionServerAuthz) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(authzData []byte) {
		dst = append(dst, pad...)
		dst = append(dst, authzData...)
		dst = append(dst, '\n')
	})
	return dst
}

func (e *ExtensionServerAuthz) AppendJSON(dst []byte) []byte {
	dst = append(dst, `"items":[`...)
	var c int
	e.Each(func(authzData []byte) {
		if c > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, '"')
		dst = append(dst, authzData...)
		dst = append(dst, '"')
		c++
	})
	dst = append(dst, ']')
	return dst
}

// ---

// ExtensionCertType represents extension "cert_type".
type ExtensionCertType struct {
	payload []byte
}

func NewExtensionCertType(payload []byte) *ExtensionCertType {
	return &ExtensionCertType{payload: payload}
}

func (e *ExtensionCertType) Length() int {
	if len(e.payload) < 1 {
		return 0
	}
	return int(e.payload[0])
}

func (e *ExtensionCertType) Each(fn func(certType byte)) {
	if len(e.payload) < 1 {
		return
	}
	count := int(e.payload[0])
	if len(e.payload) < 1+count {
		return
	}
	for i := 0; i < count; i++ {
		fn(e.payload[1+i])
	}
}

func (e *ExtensionCertType) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(certType byte) {
		dst = append(dst, pad...)
		dst = strconv.AppendInt(dst, int64(certType), 10)
		dst = append(dst, '\n')
	})
	return dst
}

func (e *ExtensionCertType) AppendJSON(dst []byte) []byte {
	dst = append(dst, `"items":[`...)
	var c int
	e.Each(func(certType byte) {
		if c > 0 {
			dst = append(dst, ',')
		}
		dst = strconv.AppendInt(dst, int64(certType), 10)
		c++
	})
	dst = append(dst, ']')
	return dst
}

// ---

// ExtensionSupportedGroups represents extension "supported_groups".
type ExtensionSupportedGroups struct {
	payload []byte
}

func NewExtensionSupportedGroups(payload []byte) *ExtensionSupportedGroups {
	return &ExtensionSupportedGroups{payload: payload}
}

func (e *ExtensionSupportedGroups) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])/2
}

func (e *ExtensionSupportedGroups) Each(fn func(group EllipticCurve)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	for i := 0; i < listLen; i += 2 {
		if 2+i+1 > len(e.payload) {
			break
		}
		group := uint16(e.payload[2+i])<<8 | uint16(e.payload[2+i+1])
		fn(EllipticCurve(group))
	}
}

func (e *ExtensionSupportedGroups) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(group EllipticCurve) {
		dst = append(dst, pad...)
		dst = fmt.Appendf(dst, "%s (0x%04x) ", group.String(), group.Raw())
		dst = append(dst, '\n')
	})
	return dst
}

func (e *ExtensionSupportedGroups) AppendJSON(dst []byte) []byte {
	dst = append(dst, `"items":[`...)
	var c int
	e.Each(func(group EllipticCurve) {
		if c > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, `{"name":"`...)
		dst = append(dst, group.String()...)
		dst = append(dst, `","value":`...)
		dst = strconv.AppendUint(dst, uint64(group.Raw()), 10)
		dst = append(dst, '}')
		c++
	})
	dst = append(dst, ']')
	return dst
}

// ---

// ExtensionECPointFormats represents extension "ec_point_formats".
type ExtensionECPointFormats struct {
	payload []byte
}

func NewExtensionECPointFormats(payload []byte) *ExtensionECPointFormats {
	return &ExtensionECPointFormats{payload: payload}
}

func (e *ExtensionECPointFormats) Length() int {
	if len(e.payload) < 1 {
		return 0
	}
	return int(e.payload[0])
}

func (e *ExtensionECPointFormats) Each(fn func(format ECPointFormats)) {
	if len(e.payload) < 1 {
		return
	}
	count := int(e.payload[0])
	if len(e.payload) < 1+count {
		return
	}
	for i := 0; i < count; i++ {
		fn(ECPointFormats(e.payload[1+i]))
	}
}

func (e *ExtensionECPointFormats) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(format ECPointFormats) {
		dst = append(dst, pad...)
		dst = fmt.Appendf(dst, "%s (0x%02x) ", format.String(), format.Raw())
		dst = append(dst, '\n')
	})
	return dst
}

func (e *ExtensionECPointFormats) AppendJSON(dst []byte) []byte {
	dst = append(dst, `"items":[`...)
	var c int
	e.Each(func(format ECPointFormats) {
		if c > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, `{"name":"`...)
		dst = append(dst, format.String()...)
		dst = append(dst, `","value":`...)
		dst = strconv.AppendUint(dst, uint64(format.Raw()), 10)
		dst = append(dst, '}')
		c++
	})
	dst = append(dst, ']')
	return dst
}

// ---

// ExtensionSRP represents extension "srp".
type ExtensionSRP struct {
	payload []byte
}

func NewExtensionSRP(payload []byte) *ExtensionSRP {
	return &ExtensionSRP{payload: payload}
}

func (e *ExtensionSRP) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionSRP) Each(fn func(identity []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		idLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+idLen > len(e.payload) {
			break
		}
		fn(e.payload[pos : pos+idLen])
		pos += idLen
	}
}

func (e *ExtensionSRP) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(identity []byte) {
		dst = append(dst, pad...)
		dst = append(dst, identity...)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionSignatureAlgorithms represents extension "signature_algorithms".
type ExtensionSignatureAlgorithms struct {
	payload []byte
}

func NewExtensionSignatureAlgorithms(payload []byte) *ExtensionSignatureAlgorithms {
	return &ExtensionSignatureAlgorithms{payload: payload}
}

func (e *ExtensionSignatureAlgorithms) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])/2
}

func (e *ExtensionSignatureAlgorithms) Each(fn func(hash byte, sa SignatureAlgorithm)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	for i := 0; i < listLen; i += 2 {
		if 2+i+1 > len(e.payload) {
			break
		}
		hash := e.payload[2+i]
		signature := e.payload[2+i+1]
		fn(hash, SignatureAlgorithm(signature))
	}
}

func (e *ExtensionSignatureAlgorithms) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(hash byte, sa SignatureAlgorithm) {
		dst = append(dst, pad...)
		dst = fmt.Appendf(dst, "%s (0x%02x) ", sa.String(), sa.Raw())
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionUseSRTP represents extension "use_srtp".
type ExtensionUseSRTP struct {
	payload []byte
}

func NewExtensionUseSRTP(payload []byte) *ExtensionUseSRTP {
	return &ExtensionUseSRTP{payload: payload}
}

func (e *ExtensionUseSRTP) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])/2
}

func (e *ExtensionUseSRTP) Each(fn func(protectionProfile uint16)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	for i := 0; i < listLen; i += 2 {
		if 2+i+1 > len(e.payload) {
			break
		}
		profile := uint16(e.payload[2+i])<<8 | uint16(e.payload[2+i+1])
		fn(profile)
	}
}

func (e *ExtensionUseSRTP) MKI() []byte {
	if len(e.payload) < 2 {
		return nil
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	mkiOffset := 2 + listLen
	if len(e.payload) < mkiOffset+1 {
		return nil
	}
	mkiLen := int(e.payload[mkiOffset])
	if len(e.payload) < mkiOffset+1+mkiLen {
		return nil
	}
	return e.payload[mkiOffset+1 : mkiOffset+1+mkiLen]
}

func (e *ExtensionUseSRTP) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = append(dst, e.MKI()...)
	dst = append(dst, '\n')
	e.Each(func(profile uint16) {
		dst = append(dst, pad...)
		dst = strconv.AppendInt(dst, int64(profile), 10)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionHeartbeat represents extension "heartbeat".
type ExtensionHeartbeat struct {
	payload []byte
}

func NewExtensionHeartbeat(payload []byte) *ExtensionHeartbeat {
	return &ExtensionHeartbeat{payload: payload}
}

func (e *ExtensionHeartbeat) Mode() byte {
	if len(e.payload) < 1 {
		return 0
	}
	return e.payload[0]
}

func (e *ExtensionHeartbeat) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = strconv.AppendInt(dst, int64(e.Mode()), 10)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionApplicationLayerProtocolNegotiation represents extension "application_layer_protocol_negotiation".
type ExtensionApplicationLayerProtocolNegotiation struct {
	payload []byte
}

func NewExtensionApplicationLayerProtocolNegotiation(payload []byte) *ExtensionApplicationLayerProtocolNegotiation {
	return &ExtensionApplicationLayerProtocolNegotiation{payload: payload}
}

func (e *ExtensionApplicationLayerProtocolNegotiation) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionApplicationLayerProtocolNegotiation) Each(fn func(protocol []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+1 > len(e.payload) {
			break
		}
		protoLen := int(e.payload[pos])
		pos++
		if pos+protoLen > len(e.payload) {
			break
		}
		fn(e.payload[pos : pos+protoLen])
		pos += protoLen
	}
}

func (e *ExtensionApplicationLayerProtocolNegotiation) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(protocol []byte) {
		dst = append(dst, pad...)
		dst = append(dst, protocol...)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionStatusRequestV2 represents extension "status_request_v2".
type ExtensionStatusRequestV2 struct {
	payload []byte
}

func NewExtensionStatusRequestV2(payload []byte) *ExtensionStatusRequestV2 {
	return &ExtensionStatusRequestV2{payload: payload}
}

func (e *ExtensionStatusRequestV2) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionStatusRequestV2) Each(fn func(statusType byte, requestData []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+1 > len(e.payload) {
			break
		}
		statusType := e.payload[pos]
		pos++
		if pos+2 > len(e.payload) {
			break
		}
		reqLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+reqLen > len(e.payload) {
			break
		}
		fn(statusType, e.payload[pos:pos+reqLen])
		pos += reqLen
	}
}

func (e *ExtensionStatusRequestV2) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(statusType byte, requestData []byte) {
		dst = append(dst, pad...)
		dst = append(dst, "type="...)
		dst = strconv.AppendInt(dst, int64(statusType), 10)
		dst = append(dst, " data="...)
		dst = append(dst, requestData...)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionSignedCertificateTimestamp represents extension "signed_certificate_timestamp".
type ExtensionSignedCertificateTimestamp struct {
	payload []byte
}

func NewExtensionSignedCertificateTimestamp(payload []byte) *ExtensionSignedCertificateTimestamp {
	return &ExtensionSignedCertificateTimestamp{payload: payload}
}

func (e *ExtensionSignedCertificateTimestamp) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionSignedCertificateTimestamp) Each(fn func(timestamp []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		tsLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+tsLen > len(e.payload) {
			break
		}
		fn(e.payload[pos : pos+tsLen])
		pos += tsLen
	}
}

func (e *ExtensionSignedCertificateTimestamp) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(timestamp []byte) {
		dst = append(dst, pad...)
		dst = append(dst, timestamp...)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionClientCertificateType represents extension "client_certificate_type".
type ExtensionClientCertificateType struct {
	payload []byte
}

func NewExtensionClientCertificateType(payload []byte) *ExtensionClientCertificateType {
	return &ExtensionClientCertificateType{payload: payload}
}

func (e *ExtensionClientCertificateType) Length() int {
	if len(e.payload) < 1 {
		return 0
	}
	return int(e.payload[0])
}

func (e *ExtensionClientCertificateType) Each(fn func(certType ClientCertificateType)) {
	if len(e.payload) < 1 {
		return
	}
	count := int(e.payload[0])
	if len(e.payload) < 1+count {
		return
	}
	for i := 0; i < count; i++ {
		fn(ClientCertificateType(e.payload[1+i]))
	}
}

func (e *ExtensionClientCertificateType) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(certType ClientCertificateType) {
		dst = append(dst, pad...)
		dst = fmt.Appendf(dst, "%s (0x%02x) ", certType.String(), certType.Raw())
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionServerCertificateType represents extension "server_certificate_type".
type ExtensionServerCertificateType struct {
	payload []byte
}

func NewExtensionServerCertificateType(payload []byte) *ExtensionServerCertificateType {
	return &ExtensionServerCertificateType{payload: payload}
}

func (e *ExtensionServerCertificateType) Length() int {
	if len(e.payload) < 1 {
		return 0
	}
	return int(e.payload[0])
}

func (e *ExtensionServerCertificateType) Each(fn func(certType ClientCertificateType)) {
	if len(e.payload) < 1 {
		return
	}
	count := int(e.payload[0])
	if len(e.payload) < 1+count {
		return
	}
	for i := 0; i < count; i++ {
		fn(ClientCertificateType(e.payload[1+i]))
	}
}

func (e *ExtensionServerCertificateType) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(certType ClientCertificateType) {
		dst = append(dst, pad...)
		dst = fmt.Appendf(dst, "%s (0x%02x) ", certType.String(), certType.Raw())
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionPadding represents extension "padding".
type ExtensionPadding struct {
	payload []byte
}

func NewExtensionPadding(payload []byte) *ExtensionPadding {
	return &ExtensionPadding{payload: payload}
}

func (e *ExtensionPadding) Length() int {
	return len(e.payload)
}

func (e *ExtensionPadding) Each(fn func(paddingByte byte)) {
	for _, b := range e.payload {
		fn(b)
	}
}

func (e *ExtensionPadding) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = strconv.AppendInt(dst, int64(e.Length()), 10)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionEncryptThenMAC represents extension "encrypt_then_mac".
type ExtensionEncryptThenMAC struct {
	payload []byte
}

func NewExtensionEncryptThenMAC(payload []byte) *ExtensionEncryptThenMAC {
	return &ExtensionEncryptThenMAC{payload: payload}
}

func (e *ExtensionEncryptThenMAC) AppendDescription(dst []byte, pad string) []byte {
	_ = pad
	return dst
}

// ---

// ExtensionExtendedMainSecret represents extension "extended_main_secret".
type ExtensionExtendedMainSecret struct {
	payload []byte
}

func NewExtensionExtendedMainSecret(payload []byte) *ExtensionExtendedMainSecret {
	return &ExtensionExtendedMainSecret{payload: payload}
}

func (e *ExtensionExtendedMainSecret) AppendDescription(dst []byte, pad string) []byte {
	_ = pad
	return dst
}

// ---

// ExtensionTokenBinding represents extension "token_binding".
type ExtensionTokenBinding struct {
	payload []byte
}

func NewExtensionTokenBinding(payload []byte) *ExtensionTokenBinding {
	return &ExtensionTokenBinding{payload: payload}
}

func (e *ExtensionTokenBinding) Version() byte {
	if len(e.payload) < 1 {
		return 0
	}
	return e.payload[0]
}

func (e *ExtensionTokenBinding) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[1])
}

func (e *ExtensionTokenBinding) Each(fn func(keyParams byte)) {
	if len(e.payload) < 2 {
		return
	}
	count := int(e.payload[1])
	if len(e.payload) < 2+count {
		return
	}
	for i := 0; i < count; i++ {
		fn(e.payload[2+i])
	}
}

func (e *ExtensionTokenBinding) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = append(dst, "version="...)
	dst = strconv.AppendInt(dst, int64(e.Version()), 10)
	dst = append(dst, '\n')
	e.Each(func(keyParams byte) {
		dst = append(dst, pad...)
		dst = append(dst, '\t')
		dst = strconv.AppendInt(dst, int64(keyParams), 10)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionCachedInfo represents extension "cached_info".
type ExtensionCachedInfo struct {
	payload []byte
}

func NewExtensionCachedInfo(payload []byte) *ExtensionCachedInfo {
	return &ExtensionCachedInfo{payload: payload}
}

func (e *ExtensionCachedInfo) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionCachedInfo) Each(fn func(cachedType byte, data []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+1 > len(e.payload) {
			break
		}
		cachedType := e.payload[pos]
		pos++
		if pos+2 > len(e.payload) {
			break
		}
		dataLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+dataLen > len(e.payload) {
			break
		}
		fn(cachedType, e.payload[pos:pos+dataLen])
		pos += dataLen
	}
}

func (e *ExtensionCachedInfo) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(cachedType byte, data []byte) {
		dst = append(dst, pad...)
		dst = append(dst, "type="...)
		dst = strconv.AppendInt(dst, int64(cachedType), 10)
		dst = append(dst, " data="...)
		dst = append(dst, data...)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionTLSLTS represents extension "tls_lts".
type ExtensionTLSLTS struct {
	payload []byte
}

func NewExtensionTLSLTS(payload []byte) *ExtensionTLSLTS {
	return &ExtensionTLSLTS{payload: payload}
}

func (e *ExtensionTLSLTS) Length() int {
	return len(e.payload)
}

func (e *ExtensionTLSLTS) Each(fn func(data []byte)) {
	if len(e.payload) < 2 {
		return
	}
	pos := 0
	for pos < len(e.payload) {
		if pos+2 > len(e.payload) {
			break
		}
		itemLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+itemLen > len(e.payload) {
			break
		}
		fn(e.payload[pos : pos+itemLen])
		pos += itemLen
	}
}

func (e *ExtensionTLSLTS) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, "tls_lts ["...)
	dst = strconv.AppendInt(dst, int64(len(e.payload)), 10)
	dst = append(dst, " bytes] "...)
	e.Each(func(data []byte) {
		dst = append(dst, data...)
		dst = append(dst, ' ')
	})
	return dst
}

// ---

// ExtensionCompressCertificate represents extension "compress_certificate".
type ExtensionCompressCertificate struct {
	payload []byte
}

func NewExtensionCompressCertificate(payload []byte) *ExtensionCompressCertificate {
	return &ExtensionCompressCertificate{payload: payload}
}

func (e *ExtensionCompressCertificate) Length() int {
	if len(e.payload) < 1 {
		return 0
	}
	return int(e.payload[0])
}

func (e *ExtensionCompressCertificate) Each(fn func(algorithm uint16)) {
	if len(e.payload) < 1 {
		return
	}
	count := int(e.payload[0])
	if len(e.payload) < 1+count*2 {
		return
	}
	for i := 0; i < count; i++ {
		algo := uint16(e.payload[1+2*i])<<8 | uint16(e.payload[1+2*i+1])
		fn(algo)
	}
}

func (e *ExtensionCompressCertificate) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(algorithm uint16) {
		dst = append(dst, pad...)
		dst = strconv.AppendInt(dst, int64(algorithm), 10)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionRecordSizeLimit represents extension "record_size_limit".
type ExtensionRecordSizeLimit struct {
	payload []byte
}

func NewExtensionRecordSizeLimit(payload []byte) *ExtensionRecordSizeLimit {
	return &ExtensionRecordSizeLimit{payload: payload}
}

func (e *ExtensionRecordSizeLimit) Limit() uint16 {
	if len(e.payload) < 2 {
		return 0
	}
	return uint16(e.payload[0])<<8 | uint16(e.payload[1])
}

func (e *ExtensionRecordSizeLimit) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = strconv.AppendInt(dst, int64(e.Limit()), 10)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionPWDProtect represents extension "pwd_protect".
type ExtensionPWDProtect struct {
	payload []byte
}

func NewExtensionPWDProtect(payload []byte) *ExtensionPWDProtect {
	return &ExtensionPWDProtect{payload: payload}
}

func (e *ExtensionPWDProtect) Length() int {
	return len(e.payload)
}

func (e *ExtensionPWDProtect) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = strconv.AppendInt(dst, int64(e.Length()), 10)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionPWDClear represents extension "pwd_clear".
type ExtensionPWDClear struct {
	payload []byte
}

func NewExtensionPWDClear(payload []byte) *ExtensionPWDClear {
	return &ExtensionPWDClear{payload: payload}
}

func (e *ExtensionPWDClear) Length() int {
	return len(e.payload)
}

func (e *ExtensionPWDClear) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = strconv.AppendInt(dst, int64(e.Length()), 10)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionPasswordSalt represents extension "password_salt".
type ExtensionPasswordSalt struct {
	payload []byte
}

func NewExtensionPasswordSalt(payload []byte) *ExtensionPasswordSalt {
	return &ExtensionPasswordSalt{payload: payload}
}

func (e *ExtensionPasswordSalt) Length() int {
	return len(e.payload)
}

func (e *ExtensionPasswordSalt) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = strconv.AppendInt(dst, int64(e.Length()), 10)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionTicketPinning represents extension "ticket_pinning".
type ExtensionTicketPinning struct {
	payload []byte
}

func NewExtensionTicketPinning(payload []byte) *ExtensionTicketPinning {
	return &ExtensionTicketPinning{payload: payload}
}

func (e *ExtensionTicketPinning) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionTicketPinning) Each(fn func(pinKey []byte, pin []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		keyLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+keyLen > len(e.payload) {
			break
		}
		pinKey := e.payload[pos : pos+keyLen]
		pos += keyLen
		if pos+2 > len(e.payload) {
			break
		}
		pinLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+pinLen > len(e.payload) {
			break
		}
		fn(pinKey, e.payload[pos:pos+pinLen])
		pos += pinLen
	}
}

func (e *ExtensionTicketPinning) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(pinKey []byte, pin []byte) {
		dst = append(dst, pad...)
		dst = append(dst, "key="...)
		dst = append(dst, pinKey...)
		dst = append(dst, " pin="...)
		dst = append(dst, pin...)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionTLSCertWithExternPSK represents extension "tls_cert_with_extern_psk".
type ExtensionTLSCertWithExternPSK struct {
	payload []byte
}

func NewExtensionTLSCertWithExternPSK(payload []byte) *ExtensionTLSCertWithExternPSK {
	return &ExtensionTLSCertWithExternPSK{payload: payload}
}

func (e *ExtensionTLSCertWithExternPSK) AppendDescription(dst []byte, pad string) []byte {
	_ = pad
	return dst
}

// ---

// ExtensionDelegatedCredential represents extension "delegated_credential".
type ExtensionDelegatedCredential struct {
	payload []byte
}

func NewExtensionDelegatedCredential(payload []byte) *ExtensionDelegatedCredential {
	return &ExtensionDelegatedCredential{payload: payload}
}

func (e *ExtensionDelegatedCredential) Length() int {
	if len(e.payload) < 3 {
		return 0
	}
	return int(e.payload[0])<<16 | int(e.payload[1])<<8 | int(e.payload[2])
}

func (e *ExtensionDelegatedCredential) Each(fn func(hash, signature byte, publicKey []byte)) {
	if len(e.payload) < 3 {
		return
	}
	listLen := int(e.payload[0])<<16 | int(e.payload[1])<<8 | int(e.payload[2])
	if len(e.payload) < 3+listLen {
		return
	}
	pos := 3
	for pos < 3+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		hash := e.payload[pos]
		signature := e.payload[pos+1]
		pos += 2
		if pos+2 > len(e.payload) {
			break
		}
		keyLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+keyLen > len(e.payload) {
			break
		}
		fn(hash, signature, e.payload[pos:pos+keyLen])
		pos += keyLen
	}
}

func (e *ExtensionDelegatedCredential) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(hash, signature byte, publicKey []byte) {
		dst = append(dst, pad...)
		dst = strconv.AppendInt(dst, int64(hash), 10)
		dst = append(dst, '/')
		dst = strconv.AppendInt(dst, int64(signature), 10)
		dst = append(dst, " key="...)
		dst = append(dst, publicKey...)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionSessionTicket represents extension "session_ticket".
type ExtensionSessionTicket struct {
	payload []byte
}

func NewExtensionSessionTicket(payload []byte) *ExtensionSessionTicket {
	return &ExtensionSessionTicket{payload: payload}
}

func (e *ExtensionSessionTicket) Ticket() []byte {
	return e.payload
}

func (e *ExtensionSessionTicket) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = strconv.AppendInt(dst, int64(len(e.Ticket())), 10)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionTLMSP represents extension "TLMSP".
type ExtensionTLMSP struct {
	payload []byte
}

func NewExtensionTLMSP(payload []byte) *ExtensionTLMSP {
	return &ExtensionTLMSP{payload: payload}
}

func (e *ExtensionTLMSP) Length() int {
	return len(e.payload)
}

func (e *ExtensionTLMSP) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = fmt.Appendf(dst, "%X", e.payload)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionTLMSPProxying represents extension "TLMSP_proxying".
type ExtensionTLMSPProxying struct {
	payload []byte
}

func NewExtensionTLMSPProxying(payload []byte) *ExtensionTLMSPProxying {
	return &ExtensionTLMSPProxying{payload: payload}
}

func (e *ExtensionTLMSPProxying) Length() int {
	return len(e.payload)
}

func (e *ExtensionTLMSPProxying) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = fmt.Appendf(dst, "%X", e.payload)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionTLMSPDelegate represents extension "TLMSP_delegate".
type ExtensionTLMSPDelegate struct {
	payload []byte
}

func NewExtensionTLMSPDelegate(payload []byte) *ExtensionTLMSPDelegate {
	return &ExtensionTLMSPDelegate{payload: payload}
}

func (e *ExtensionTLMSPDelegate) Length() int {
	return len(e.payload)
}

func (e *ExtensionTLMSPDelegate) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = fmt.Appendf(dst, "%X", e.payload)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionSupportedEKTCiphers represents extension "supported_ekt_ciphers".
type ExtensionSupportedEKTCiphers struct {
	payload []byte
}

func NewExtensionSupportedEKTCiphers(payload []byte) *ExtensionSupportedEKTCiphers {
	return &ExtensionSupportedEKTCiphers{payload: payload}
}

func (e *ExtensionSupportedEKTCiphers) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])/2
}

func (e *ExtensionSupportedEKTCiphers) Each(fn func(cipher uint16)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	for i := 0; i < listLen; i += 2 {
		if 2+i+1 > len(e.payload) {
			break
		}
		cipher := uint16(e.payload[2+i])<<8 | uint16(e.payload[2+i+1])
		fn(cipher)
	}
}

func (e *ExtensionSupportedEKTCiphers) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(cipher uint16) {
		dst = append(dst, pad...)
		dst = fmt.Appendf(dst, "0x%04x", cipher)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionPreSharedKey represents extension "pre_shared_key".
type ExtensionPreSharedKey struct {
	payload []byte
}

func NewExtensionPreSharedKey(payload []byte) *ExtensionPreSharedKey {
	return &ExtensionPreSharedKey{payload: payload}
}

func (e *ExtensionPreSharedKey) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionPreSharedKey) Each(fn func(identity []byte, obfuscatedTicketAge uint32)) {
	if len(e.payload) < 2 {
		return
	}
	identitiesLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+identitiesLen {
		return
	}
	pos := 2
	for pos < 2+identitiesLen {
		if pos+2 > len(e.payload) {
			break
		}
		idLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+idLen > len(e.payload) {
			break
		}
		identity := e.payload[pos : pos+idLen]
		pos += idLen
		if pos+4 > len(e.payload) {
			break
		}
		obfuscatedTicketAge := uint32(e.payload[pos])<<24 | uint32(e.payload[pos+1])<<16 | uint32(e.payload[pos+2])<<8 | uint32(e.payload[pos+3])
		pos += 4
		fn(identity, obfuscatedTicketAge)
	}
	if pos+2 <= len(e.payload) {
		bindersLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		_ = bindersLen
		// todo binders parsing omitted for brevity
	}
}

func (e *ExtensionPreSharedKey) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(identity []byte, obfuscatedTicketAge uint32) {
		dst = append(dst, pad...)
		dst = append(dst, "id="...)
		dst = append(dst, identity...)
		dst = append(dst, " age="...)
		dst = strconv.AppendInt(dst, int64(obfuscatedTicketAge), 10)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionEarlyData represents extension "early_data".
type ExtensionEarlyData struct {
	payload []byte
}

func NewExtensionEarlyData(payload []byte) *ExtensionEarlyData {
	return &ExtensionEarlyData{payload: payload}
}

func (e *ExtensionEarlyData) MaxEarlyDataSize() uint32 {
	if len(e.payload) < 4 {
		return 0
	}
	return uint32(e.payload[0])<<24 | uint32(e.payload[1])<<16 | uint32(e.payload[2])<<8 | uint32(e.payload[3])
}

func (e *ExtensionEarlyData) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = append(dst, "max_size="...)
	dst = strconv.AppendInt(dst, int64(e.MaxEarlyDataSize()), 10)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionSupportedVersions represents extension "supported_versions".
type ExtensionSupportedVersions struct {
	payload []byte
}

func NewExtensionSupportedVersions(payload []byte) *ExtensionSupportedVersions {
	return &ExtensionSupportedVersions{payload: payload}
}

func (e *ExtensionSupportedVersions) Length() int {
	if len(e.payload) < 1 {
		return 0
	}
	return int(e.payload[0]) / 2
}

func (e *ExtensionSupportedVersions) Each(fn func(version MessageVersion)) {
	if len(e.payload) < 1 {
		return
	}
	versionsLen := int(e.payload[0])
	if len(e.payload) < 1+versionsLen {
		return
	}
	for i := 0; i < versionsLen; i += 2 {
		if 1+i+1 > len(e.payload) {
			break
		}
		version := MessageVersion(uint16(e.payload[1+i])<<8 | uint16(e.payload[1+i+1]))
		fn(version)
	}
}

func (e *ExtensionSupportedVersions) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(version MessageVersion) {
		dst = append(dst, pad...)
		dst = fmt.Appendf(dst, "%s (0x%04x)", version.String(), version.Raw())
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionCookie represents extension "cookie".
type ExtensionCookie struct {
	payload []byte
}

func NewExtensionCookie(payload []byte) *ExtensionCookie {
	return &ExtensionCookie{payload: payload}
}

func (e *ExtensionCookie) Cookie() []byte {
	return e.payload
}

func (e *ExtensionCookie) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = append(dst, e.Cookie()...)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionPSKKeyExchangeModes represents extension "psk_key_exchange_modes".
type ExtensionPSKKeyExchangeModes struct {
	payload []byte
}

func NewExtensionPSKKeyExchangeModes(payload []byte) *ExtensionPSKKeyExchangeModes {
	return &ExtensionPSKKeyExchangeModes{payload: payload}
}

func (e *ExtensionPSKKeyExchangeModes) Length() int {
	if len(e.payload) < 1 {
		return 0
	}
	return int(e.payload[0])
}

func (e *ExtensionPSKKeyExchangeModes) Each(fn func(mode byte)) {
	if len(e.payload) < 1 {
		return
	}
	modesLen := int(e.payload[0])
	if len(e.payload) < 1+modesLen {
		return
	}
	for i := 0; i < modesLen; i++ {
		fn(e.payload[1+i])
	}
}

func (e *ExtensionPSKKeyExchangeModes) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(mode byte) {
		dst = append(dst, pad...)
		dst = fmt.Appendf(dst, "0x%02x", mode)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionCertificateAuthorities represents extension "certificate_authorities".
type ExtensionCertificateAuthorities struct {
	payload []byte
}

func NewExtensionCertificateAuthorities(payload []byte) *ExtensionCertificateAuthorities {
	return &ExtensionCertificateAuthorities{payload: payload}
}

func (e *ExtensionCertificateAuthorities) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionCertificateAuthorities) Each(fn func(ca []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		caLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+caLen > len(e.payload) {
			break
		}
		fn(e.payload[pos : pos+caLen])
		pos += caLen
	}
}

func (e *ExtensionCertificateAuthorities) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(ca []byte) {
		dst = append(dst, pad...)
		dst = append(dst, ca...)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionOIDFilters represents extension "oid_filters".
type ExtensionOIDFilters struct {
	payload []byte
}

func NewExtensionOIDFilters(payload []byte) *ExtensionOIDFilters {
	return &ExtensionOIDFilters{payload: payload}
}

func (e *ExtensionOIDFilters) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionOIDFilters) Each(fn func(oid []byte, filter []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		oidLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+oidLen > len(e.payload) {
			break
		}
		oid := e.payload[pos : pos+oidLen]
		pos += oidLen
		if pos+2 > len(e.payload) {
			break
		}
		filterLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+filterLen > len(e.payload) {
			break
		}
		fn(oid, e.payload[pos:pos+filterLen])
		pos += filterLen
	}
}

func (e *ExtensionOIDFilters) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(oid []byte, filter []byte) {
		dst = append(dst, pad...)
		dst = append(dst, "oid="...)
		dst = append(dst, oid...)
		dst = append(dst, " filter="...)
		dst = append(dst, filter...)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionPostHandshakeAuth represents extension "post_handshake_auth".
type ExtensionPostHandshakeAuth struct {
	payload []byte
}

func NewExtensionPostHandshakeAuth(payload []byte) *ExtensionPostHandshakeAuth {
	return &ExtensionPostHandshakeAuth{payload: payload}
}

// ExtensionSignatureAlgorithmsCert represents extension "signature_algorithms_cert".
type ExtensionSignatureAlgorithmsCert struct {
	payload []byte
}

func (e *ExtensionPostHandshakeAuth) AppendDescription(dst []byte, pad string) []byte {
	_ = pad
	return dst
}

// ---

func NewExtensionSignatureAlgorithmsCert(payload []byte) *ExtensionSignatureAlgorithmsCert {
	return &ExtensionSignatureAlgorithmsCert{payload: payload}
}

func (e *ExtensionSignatureAlgorithmsCert) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])/2
}

func (e *ExtensionSignatureAlgorithmsCert) Each(fn func(hash, signature byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	for i := 0; i < listLen; i += 2 {
		if 2+i+1 > len(e.payload) {
			break
		}
		hash := e.payload[2+i]
		signature := e.payload[2+i+1]
		fn(hash, signature)
	}
}

func (e *ExtensionSignatureAlgorithmsCert) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(hash, signature byte) {
		dst = append(dst, pad...)
		dst = strconv.AppendInt(dst, int64(hash), 10)
		dst = append(dst, '/')
		dst = strconv.AppendInt(dst, int64(signature), 10)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionKeyShare represents extension "key_share".
type ExtensionKeyShare struct {
	payload []byte
}

func NewExtensionKeyShare(payload []byte) *ExtensionKeyShare {
	return &ExtensionKeyShare{payload: payload}
}

func (e *ExtensionKeyShare) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionKeyShare) Each(fn func(group uint16, keyExchange []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		group := uint16(e.payload[pos])<<8 | uint16(e.payload[pos+1])
		pos += 2
		if pos+2 > len(e.payload) {
			break
		}
		keyLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+keyLen > len(e.payload) {
			break
		}
		fn(group, e.payload[pos:pos+keyLen])
		pos += keyLen
	}
}

func (e *ExtensionKeyShare) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(group uint16, keyExchange []byte) {
		dst = append(dst, pad...)
		dst = append(dst, "group="...)
		dst = strconv.AppendInt(dst, int64(group), 10)
		dst = append(dst, " key="...)
		dst = fmt.Appendf(dst, "%X", keyExchange)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionTransparencyInfo represents extension "transparency_info".
type ExtensionTransparencyInfo struct {
	payload []byte
}

func NewExtensionTransparencyInfo(payload []byte) *ExtensionTransparencyInfo {
	return &ExtensionTransparencyInfo{payload: payload}
}

func (e *ExtensionTransparencyInfo) Length() int {
	return len(e.payload)
}

func (e *ExtensionTransparencyInfo) AppendDescription(dst []byte, pad string) []byte {
	dst = fmt.Appendf(dst, "%X", e.payload)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionConnectionID represents extension "connection_id".
type ExtensionConnectionID struct {
	payload []byte
}

func NewExtensionConnectionID(payload []byte) *ExtensionConnectionID {
	return &ExtensionConnectionID{payload: payload}
}

func (e *ExtensionConnectionID) CID() []byte {
	return e.payload
}

func (e *ExtensionConnectionID) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = append(dst, "cid="...)
	dst = append(dst, e.CID()...)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionExternalIDHash represents extension "external_id_hash".
type ExtensionExternalIDHash struct {
	payload []byte
}

func NewExtensionExternalIDHash(payload []byte) *ExtensionExternalIDHash {
	return &ExtensionExternalIDHash{payload: payload}
}

func (e *ExtensionExternalIDHash) Hash() []byte {
	return e.payload
}

func (e *ExtensionExternalIDHash) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = append(dst, "hash="...)
	dst = append(dst, e.Hash()...)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionExternalSessionID represents extension "external_session_id".
type ExtensionExternalSessionID struct {
	payload []byte
}

func NewExtensionExternalSessionID(payload []byte) *ExtensionExternalSessionID {
	return &ExtensionExternalSessionID{payload: payload}
}

func (e *ExtensionExternalSessionID) ID() []byte {
	return e.payload
}

func (e *ExtensionExternalSessionID) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = append(dst, "id="...)
	dst = append(dst, e.ID()...)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionQUICTransportParameters represents extension "quic_transport_parameters".
type ExtensionQUICTransportParameters struct {
	payload []byte
}

func NewExtensionQUICTransportParameters(payload []byte) *ExtensionQUICTransportParameters {
	return &ExtensionQUICTransportParameters{payload: payload}
}

func (e *ExtensionQUICTransportParameters) Parameters() []byte {
	return e.payload
}

func (e *ExtensionQUICTransportParameters) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = append(dst, e.payload...)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionTicketRequest represents extension "ticket_request".
type ExtensionTicketRequest struct {
	payload []byte
}

func NewExtensionTicketRequest(payload []byte) *ExtensionTicketRequest {
	return &ExtensionTicketRequest{payload: payload}
}

func (e *ExtensionTicketRequest) AppendDescription(dst []byte, pad string) []byte {
	_ = pad
	return dst
}

// ---

// ExtensionDNSSECChain represents extension "dnssec_chain".
type ExtensionDNSSECChain struct {
	payload []byte
}

func NewExtensionDNSSECChain(payload []byte) *ExtensionDNSSECChain {
	return &ExtensionDNSSECChain{payload: payload}
}

func (e *ExtensionDNSSECChain) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionDNSSECChain) Each(fn func(chainData []byte)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	pos := 2
	for pos < 2+listLen {
		if pos+2 > len(e.payload) {
			break
		}
		dataLen := int(e.payload[pos])<<8 | int(e.payload[pos+1])
		pos += 2
		if pos+dataLen > len(e.payload) {
			break
		}
		fn(e.payload[pos : pos+dataLen])
		pos += dataLen
	}
}

func (e *ExtensionDNSSECChain) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(chainData []byte) {
		dst = append(dst, pad...)
		dst = append(dst, chainData...)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionSequenceNumberEncryptionAlgorithms represents extension "sequence_number_encryption_algorithms".
type ExtensionSequenceNumberEncryptionAlgorithms struct {
	payload []byte
}

func NewExtensionSequenceNumberEncryptionAlgorithms(payload []byte) *ExtensionSequenceNumberEncryptionAlgorithms {
	return &ExtensionSequenceNumberEncryptionAlgorithms{payload: payload}
}

func (e *ExtensionSequenceNumberEncryptionAlgorithms) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])/2
}

func (e *ExtensionSequenceNumberEncryptionAlgorithms) Each(fn func(algo uint16)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	for i := 0; i < listLen; i += 2 {
		if 2+i+1 > len(e.payload) {
			break
		}
		algo := uint16(e.payload[2+i])<<8 | uint16(e.payload[2+i+1])
		fn(algo)
	}
}

func (e *ExtensionSequenceNumberEncryptionAlgorithms) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(algo uint16) {
		dst = append(dst, pad...)
		dst = fmt.Appendf(dst, "0x%04x", algo)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionRRC represents extension "rrc".
type ExtensionRRC struct {
	payload []byte
}

func NewExtensionRRC(payload []byte) *ExtensionRRC {
	return &ExtensionRRC{payload: payload}
}

func (e *ExtensionRRC) AppendDescription(dst []byte, pad string) []byte {
	_ = pad
	return dst
}

// ---

// ExtensionTLSFlags represents extension "tls_flags".
type ExtensionTLSFlags struct {
	payload []byte
}

func NewExtensionTLSFlags(payload []byte) *ExtensionTLSFlags {
	return &ExtensionTLSFlags{payload: payload}
}

func (e *ExtensionTLSFlags) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionTLSFlags) Each(fn func(flag uint32)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen*4 {
		return
	}
	for i := 0; i < listLen; i++ {
		flag := uint32(e.payload[2+4*i])<<24 | uint32(e.payload[2+4*i+1])<<16 | uint32(e.payload[2+4*i+2])<<8 | uint32(e.payload[2+4*i+3])
		fn(flag)
	}
}

func (e *ExtensionTLSFlags) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(flag uint32) {
		dst = append(dst, pad...)
		dst = fmt.Appendf(dst, "0x%08x", flag)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionECHOuterExtensions represents extension "ech_outer_extensions".
type ExtensionECHOuterExtensions struct {
	payload []byte
}

func NewExtensionECHOuterExtensions(payload []byte) *ExtensionECHOuterExtensions {
	return &ExtensionECHOuterExtensions{payload: payload}
}

func (e *ExtensionECHOuterExtensions) Length() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])/2
}

func (e *ExtensionECHOuterExtensions) Each(fn func(extType uint16)) {
	if len(e.payload) < 2 {
		return
	}
	listLen := int(e.payload[0])<<8 | int(e.payload[1])
	if len(e.payload) < 2+listLen {
		return
	}
	for i := 0; i < listLen; i += 2 {
		if 2+i+1 > len(e.payload) {
			break
		}
		extType := uint16(e.payload[2+i])<<8 | uint16(e.payload[2+i+1])
		fn(extType)
	}
}

func (e *ExtensionECHOuterExtensions) AppendDescription(dst []byte, pad string) []byte {
	e.Each(func(extType uint16) {
		dst = append(dst, pad...)
		dst = fmt.Appendf(dst, "0x%04x", extType)
		dst = append(dst, '\n')
	})
	return dst
}

// ---

// ExtensionEncryptedClientHello represents extension "encrypted_client_hello".
type ExtensionEncryptedClientHello struct {
	payload []byte
}

func NewExtensionEncryptedClientHello(payload []byte) *ExtensionEncryptedClientHello {
	return &ExtensionEncryptedClientHello{payload: payload}
}

func (e *ExtensionEncryptedClientHello) ConfigIDLength() int {
	if len(e.payload) < 2 {
		return 0
	}
	return int(e.payload[0])<<8 | int(e.payload[1])
}

func (e *ExtensionEncryptedClientHello) Each(fn func(cipherSuite uint16, keyExchange []byte, encryptedExtensions []byte)) {
	// todo implement me
}

func (e *ExtensionEncryptedClientHello) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = append(dst, "config_id_len="...)
	dst = strconv.AppendInt(dst, int64(e.ConfigIDLength()), 10)
	dst = append(dst, '\n')
	return dst
}

// ---

// ExtensionRenegotiationInfo represents extension "renegotiation_info".
type ExtensionRenegotiationInfo struct {
	payload []byte
}

func NewExtensionRenegotiationInfo(payload []byte) *ExtensionRenegotiationInfo {
	return &ExtensionRenegotiationInfo{payload: payload}
}

func (e *ExtensionRenegotiationInfo) VerifiedData() []byte {
	return e.payload
}

func (e *ExtensionRenegotiationInfo) AppendDescription(dst []byte, pad string) []byte {
	dst = append(dst, pad...)
	dst = append(dst, "verified_data="...)
	dst = fmt.Appendf(dst, "%X", e.payload)
	dst = append(dst, '\n')
	return dst
}
