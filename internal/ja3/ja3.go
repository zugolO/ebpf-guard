// Package ja3 provides TLS fingerprint computation (JA3/JA3S/JA4) for C2 detection.
//
// JA3 (2017, Salesforce) fingerprints TLS ClientHello messages by concatenating
// decimal values of TLS version, cipher suites, extensions, elliptic curves, and
// EC point formats, then computing an MD5 hash.
//
// JA3S is the server-side variant using the ServerHello message.
//
// JA4 (2023, FoxIO) is the successor to JA3, using a more structured format:
//
//	Protocol_TLSVersion_SNI_CiphersNumber_CiphersHash_ExtensionsHash
//
// References:
//   - JA3: https://github.com/salesforce/ja3
//   - JA4: https://github.com/FoxIO-LLC/ja4
package ja3

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ClientHelloFields holds the parsed fields extracted from a TLS ClientHello.
type ClientHelloFields struct {
	Version     uint16   // TLS protocol version from ClientHello (e.g. 0x0303 = TLS 1.2)
	Ciphers     []uint16 // cipher suite IDs in order of appearance
	Extensions  []uint16 // extension type IDs in order of appearance
	Curves      []uint16 // supported elliptic curves (extension 10)
	PointFmts   []uint8  // EC point formats (extension 11)
	SNI         string   // Server Name Indication (extension 0)
	ALPN        []string // Application-Layer Protocol Negotiation (extension 16)
	SignAlgos   []uint16 // signature algorithms (extension 13)
}

// ParseClientHello parses a raw TLS ClientHello message and extracts fields
// needed for JA3/JA4 fingerprinting.
//
// The input must be the complete TLS record (ContentType + Version + Length)
// followed by the ClientHello handshake message. It handles TLS 1.0 through 1.3.
func ParseClientHello(data []byte) (*ClientHelloFields, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("ja3: data too short for TLS record header: %d bytes", len(data))
	}

	contentType := data[0]
	if contentType != 0x16 {
		return nil, fmt.Errorf("ja3: not a TLS handshake record (type=0x%02x)", contentType)
	}

	recVersion := binary.BigEndian.Uint16(data[1:3])
	recLen := binary.BigEndian.Uint16(data[3:5])

	if int(recLen)+5 > len(data) {
		return nil, fmt.Errorf("ja3: record length %d exceeds available data", recLen)
	}

	handshake := data[5:] // skip 5-byte TLS record header
	if recLen > uint16(len(handshake)) {
		handshake = handshake[:recLen]
	}

	return parseClientHelloHandshake(handshake, recVersion)
}

// parseClientHelloHandshake parses the handshake payload of a ClientHello.
func parseClientHelloHandshake(data []byte, recVersion uint16) (*ClientHelloFields, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("ja3: handshake data too short: %d bytes", len(data))
	}

	hsType := data[0]
	if hsType != 0x01 {
		return nil, fmt.Errorf("ja3: not a ClientHello (handshake type=0x%02x)", hsType)
	}

	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if hsLen+4 > len(data) {
		return nil, fmt.Errorf("ja3: handshake length %d exceeds available data", hsLen)
	}

	body := data[4 : 4+hsLen]
	h := &ClientHelloFields{}
	off := 0

	if off+2 > len(body) {
		return nil, fmt.Errorf("ja3: body too short for version")
	}
	h.Version = binary.BigEndian.Uint16(body[off:])
	off += 2

	// Skip random (32 bytes)
	if off+32 > len(body) {
		return nil, fmt.Errorf("ja3: body too short for random")
	}
	off += 32

	// Skip session ID
	if off+1 > len(body) {
		return nil, fmt.Errorf("ja3: body too short for session ID length")
	}
	sidLen := int(body[off])
	off += 1 + sidLen

	// Cipher suites
	if off+2 > len(body) {
		return nil, fmt.Errorf("ja3: body too short for cipher suites length")
	}
	csLen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if csLen%2 != 0 || off+csLen > len(body) {
		return nil, fmt.Errorf("ja3: invalid cipher suites section")
	}
	h.Ciphers = make([]uint16, csLen/2)
	for i := 0; i < csLen/2; i++ {
		h.Ciphers[i] = binary.BigEndian.Uint16(body[off : off+2])
		off += 2
	}

	// Skip compression methods
	if off+1 > len(body) {
		return nil, fmt.Errorf("ja3: body too short for compression methods")
	}
	compLen := int(body[off])
	off += 1 + compLen

	// Extensions (may be absent in old TLS)
	if off+2 > len(body) {
		h.Extensions = nil
		h.Curves = nil
		h.PointFmts = nil
		return h, nil
	}
	extLen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	extEnd := off + extLen
	if extEnd > len(body) {
		extEnd = len(body)
	}

	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[off:])
		extDataLen := int(binary.BigEndian.Uint16(body[off+2:]))
		extData := body[off+4:]
		if extDataLen > len(extData) {
			extDataLen = len(extData)
		}
		extData = extData[:extDataLen]

		h.Extensions = append(h.Extensions, extType)

		switch extType {
		case 0: // server_name (SNI)
			// extData layout: server_name_list length (2) | name_type (1) |
			// host_name length (2) | host_name. name_type 0 = host_name.
			if len(extData) >= 5 && extData[2] == 0 {
				nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
				if 5+nameLen <= len(extData) {
					h.SNI = string(extData[5 : 5+nameLen])
				}
			}

		case 10: // supported_groups (elliptic curves)
			if len(extData) >= 2 {
				curvesLen := int(binary.BigEndian.Uint16(extData[:2]))
				curvesData := extData[2:]
				if curvesLen%2 == 0 && curvesLen <= len(curvesData) {
					h.Curves = make([]uint16, curvesLen/2)
					for i := 0; i < curvesLen/2; i++ {
						h.Curves[i] = binary.BigEndian.Uint16(curvesData[i*2:])
					}
				}
			}

		case 11: // ec_point_formats
			if len(extData) >= 1 {
				fmtLen := int(extData[0])
				if fmtLen <= len(extData)-1 {
					h.PointFmts = make([]uint8, fmtLen)
					copy(h.PointFmts, extData[1:1+fmtLen])
				}
			}

		case 13: // signature_algorithms
			if len(extData) >= 2 {
				sigLen := int(binary.BigEndian.Uint16(extData[:2]))
				sigData := extData[2:]
				if sigLen%2 == 0 && sigLen <= len(sigData) {
					h.SignAlgos = make([]uint16, sigLen/2)
					for i := 0; i < sigLen/2; i++ {
						h.SignAlgos[i] = binary.BigEndian.Uint16(sigData[i*2:])
					}
				}
			}

		case 16: // application_layer_protocol_negotiation (ALPN)
			if len(extData) >= 2 {
				alpnLen := int(binary.BigEndian.Uint16(extData[:2]))
				alpnData := extData[2:]
				for pos := 0; alpnLen > 0 && pos < len(alpnData); {
					if pos+1 > len(alpnData) {
						break
					}
					protoLen := int(alpnData[pos])
					pos++
					if pos+protoLen > len(alpnData) {
						break
					}
					if protoLen > 0 {
						h.ALPN = append(h.ALPN, string(alpnData[pos:pos+protoLen]))
					}
					pos += protoLen
					alpnLen -= 1 + protoLen
				}
			}
		}

		off += 4 + extDataLen
	}

	return h, nil
}

// ---------------------------------------------------------------------------
// JA3
// ---------------------------------------------------------------------------

// JA3 computes the JA3 hash for a parsed ClientHello.
// Formula: MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
// All numeric values are decimal strings, comma-separated, with hyphens for
// empty lists.
func (h *ClientHelloFields) JA3() string {
	var sb strings.Builder

	// TLS version
	fmt.Fprintf(&sb, "%d,", h.Version)

	// Cipher suites — in wire order (NOT sorted); JA3 spec requires original order.
	if len(h.Ciphers) == 0 {
		sb.WriteString("-,")
	} else {
		for i, c := range h.Ciphers {
			if i > 0 {
				sb.WriteString("-")
			}
			sb.WriteString(strconv.FormatUint(uint64(c), 10))
		}
		sb.WriteString(",")
	}

	// Extensions — in wire order (NOT sorted).
	if len(h.Extensions) == 0 {
		sb.WriteString("-,")
	} else {
		for i, e := range h.Extensions {
			if i > 0 {
				sb.WriteString("-")
			}
			sb.WriteString(strconv.FormatUint(uint64(e), 10))
		}
		sb.WriteString(",")
	}

	// Elliptic curves — in wire order (NOT sorted).
	if len(h.Curves) == 0 {
		sb.WriteString("-,")
	} else {
		for i, c := range h.Curves {
			if i > 0 {
				sb.WriteString("-")
			}
			sb.WriteString(strconv.FormatUint(uint64(c), 10))
		}
		sb.WriteString(",")
	}

	// EC point formats — in wire order (NOT sorted).
	if len(h.PointFmts) == 0 {
		sb.WriteString("-")
	} else {
		for i, f := range h.PointFmts {
			if i > 0 {
				sb.WriteString("-")
			}
			sb.WriteString(strconv.FormatUint(uint64(f), 10))
		}
	}

	return fmt.Sprintf("%x", md5.Sum([]byte(sb.String())))
}

// ComputeJA3 parses raw ClientHello data and returns the JA3 hash.
func ComputeJA3(data []byte) (string, error) {
	h, err := ParseClientHello(data)
	if err != nil {
		return "", err
	}
	return h.JA3(), nil
}

// ---------------------------------------------------------------------------
// JA3S (server-side fingerprint)
// ---------------------------------------------------------------------------

// ServerHelloFields holds parsed ServerHello information.
type ServerHelloFields struct {
	Version    uint16
	Cipher     uint16
	Extensions []uint16
}

// JA3S computes the JA3S hash for a ServerHello.
// Formula: MD5(TLSVersion,Cipher,Extensions)
func (s *ServerHelloFields) JA3S() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d,%d,", s.Version, s.Cipher)

	exts := make([]uint16, len(s.Extensions))
	copy(exts, s.Extensions)
	sortUint16(exts)
	if len(exts) == 0 {
		sb.WriteString("-")
	} else {
		for i, e := range exts {
			if i > 0 {
				sb.WriteString("-")
			}
			sb.WriteString(strconv.FormatUint(uint64(e), 10))
		}
	}

	return fmt.Sprintf("%x", md5.Sum([]byte(sb.String())))
}

// ---------------------------------------------------------------------------
// JA4
// ---------------------------------------------------------------------------

// JA4 computes the JA4 fingerprint for a parsed ClientHello.
// JA4 format:
//
//	Protocol_TLSVersion_SNI_CiphersCount_CiphersHash_ExtensionsHash
//
// Where:
//   - Protocol is always "t" (TCP TLS, as opposed to "q" for QUIC)
//   - TLSVersion: "13" for TLS 1.3, "12" for TLS 1.2, "10" for TLS 1.0, "s" for SSL
//   - SNI: "d" if there is a domain SNI (not an IP), "i" if SNI is absent
//   - CiphersCount: 2-digit decimal number of cipher suites
//   - CiphersHash: first 12 hex chars of SHA-256(sorted cipher suite hex codes)
//   - ExtensionsHash: first 12 hex chars of SHA-256(sorted extension type hex codes)
func (h *ClientHelloFields) JA4() string {
	// Protocol
	protocol := "t" // TCP TLS

	// TLS version
	var tlsVer string
	switch h.Version {
	case 0x0304:
		tlsVer = "13"
	case 0x0303:
		tlsVer = "12"
	case 0x0302:
		tlsVer = "11"
	case 0x0301:
		tlsVer = "10"
	case 0x0300:
		tlsVer = "s3"
	case 0x0002:
		tlsVer = "s2"
	default:
		tlsVer = "00"
	}

	// SNI
	sniField := "i" // absent
	if h.SNI != "" && !isIPv4Literal(h.SNI) {
		sniField = "d" // domain
	}

	// Ciphers count (2 digits)
	ciphersCount := fmt.Sprintf("%02d", len(h.Ciphers))

	// Ciphers hash: sorted cipher suite hex codes, then SHA-256, take first 12 chars
	ciphersSorted := make([]string, len(h.Ciphers))
	for i, c := range h.Ciphers {
		ciphersSorted[i] = fmt.Sprintf("%04x", c)
	}
	sort.Strings(ciphersSorted)
	ciphersHash := sha256Hex12(strings.Join(ciphersSorted, ","))

	// Extensions hash: sorted extension type hex codes, then SHA-256, take first 12 chars
	extsSorted := make([]string, len(h.Extensions))
	for i, e := range h.Extensions {
		extsSorted[i] = fmt.Sprintf("%04x", e)
	}
	sort.Strings(extsSorted)
	extsHash := sha256Hex12(strings.Join(extsSorted, ","))

	return fmt.Sprintf("%s%s%s%s%s_%s",
		protocol, tlsVer, sniField, ciphersCount, ciphersHash, extsHash)
}

// ComputeJA4 parses raw ClientHello data and returns the JA4 fingerprint.
func ComputeJA4(data []byte) (string, error) {
	h, err := ParseClientHello(data)
	if err != nil {
		return "", err
	}
	return h.JA4(), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func sortUint16(s []uint16) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}

func sortUint8(s []uint8) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}

func sha256Hex12(input string) string {
	h := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", h[:6]) // first 12 hex chars (6 bytes = 12 hex digits)
}

func isIPv4Literal(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}
