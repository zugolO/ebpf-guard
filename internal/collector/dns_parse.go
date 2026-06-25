package collector

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// dnsRawEventFixedLen is the size of struct dns_event in dns.bpf.c up to
// (but not including) the variable-meaningful payload bytes: type(4) +
// timestamp(8) + pid(4) + tgid(4) + uid(4) + comm(16) + direction(1) +
// payload_len(2) = 43. The struct is packed, so there is no padding.
const dnsRawEventFixedLen = 4 + 8 + 4 + 4 + 4 + 16 + 1 + 2

// dnsMaxPayload mirrors DNS_MAX_PAYLOAD in dns.bpf.c — the kernel side
// always reserves this many payload bytes in the ring buffer record,
// truncating longer messages rather than dropping them.
const dnsMaxPayload = 256

// dnsMaxNameJumps bounds compression-pointer chasing in decodeDNSName so a
// crafted or corrupted message can't cause an infinite loop. There is no
// BPF verifier here — this is a plain userspace safety limit.
const dnsMaxNameJumps = 32

// decodeDNSEvent parses a raw ring buffer record into a types.Event. It has no
// kernel dependencies — it only decodes bytes — so it is unit-tested directly
// without a running probe.
//
// The BPF side (dns.bpf.c) no longer decodes the DNS wire format — it just
// captures the raw UDP payload, so all QNAME/QTYPE/RCODE/answer parsing,
// including compression-pointer chasing, happens here where there's no
// verifier instruction budget to fight. A nil return means the record is not a
// usable DNS event (too short, wrong type, or an unparseable message).
func decodeDNSEvent(raw []byte) *types.Event {
	if len(raw) < dnsRawEventFixedLen {
		return nil
	}

	// Parse the fixed dns_event header. Layout matches struct dns_event in
	// dns.bpf.c.
	offset := 0

	// type (4 bytes)
	eventType := binary.LittleEndian.Uint32(raw[offset:])
	offset += 4

	if eventType != uint32(types.EventDNS) {
		return nil
	}

	// timestamp (8 bytes)
	timestamp := binary.LittleEndian.Uint64(raw[offset:])
	offset += 8

	// pid (4 bytes)
	pid := binary.LittleEndian.Uint32(raw[offset:])
	offset += 4

	// tgid (4 bytes)
	tgid := binary.LittleEndian.Uint32(raw[offset:])
	offset += 4

	// uid (4 bytes)
	uid := binary.LittleEndian.Uint32(raw[offset:])
	offset += 4

	// comm (16 bytes)
	var comm [16]byte
	copy(comm[:], raw[offset:])
	offset += 16

	// direction (1 byte)
	direction := types.DNSDirection(raw[offset])
	offset += 1

	// payload_len (2 bytes)
	payloadLen := binary.LittleEndian.Uint16(raw[offset:])
	offset += 2

	if int(payloadLen) > dnsMaxPayload || offset+int(payloadLen) > len(raw) {
		return nil
	}
	payload := raw[offset : offset+int(payloadLen)]

	msg, ok := parseDNSWireMessage(payload)
	if !ok {
		return nil
	}

	return &types.Event{
		Type:      types.EventDNS,
		Timestamp: timestamp,
		PID:       pid,
		TGID:      tgid,
		UID:       uid,
		Comm:      comm,
		DNS: &types.DNSEvent{
			QName:       msg.qname,
			QType:       msg.qtype,
			RCode:       msg.rcode,
			Direction:   direction,
			ResponseIPs: msg.responseIPs,
		},
	}
}

// dnsWireMessage holds the fields the rest of the system cares about,
// decoded from a raw DNS message captured by the BPF side.
type dnsWireMessage struct {
	qname       string
	qtype       uint16
	rcode       uint16
	responseIPs []string
}

// parseDNSWireMessage decodes a raw DNS message (header + question, and
// answer records for responses) per RFC 1035. Unlike the in-kernel decoder
// it replaces, this correctly follows compression pointers in QNAME/answer
// names since there's no verifier-imposed bound on loop complexity here.
func parseDNSWireMessage(payload []byte) (dnsWireMessage, bool) {
	var msg dnsWireMessage

	if len(payload) < 12 {
		return msg, false
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	isResponse := flags&0x8000 != 0
	msg.rcode = flags & 0x000f

	qdCount := binary.BigEndian.Uint16(payload[4:6])
	anCount := binary.BigEndian.Uint16(payload[6:8])
	if qdCount == 0 {
		return msg, false
	}

	pos := 12
	qname, pos, ok := decodeDNSName(payload, pos)
	if !ok {
		return msg, false
	}
	msg.qname = qname

	if pos+4 > len(payload) {
		// Got the name but not QTYPE/QCLASS; still useful to the caller.
		return msg, true
	}
	msg.qtype = binary.BigEndian.Uint16(payload[pos : pos+2])
	pos += 4 // QTYPE (2) + QCLASS (2)

	if isResponse {
		msg.responseIPs = decodeDNSAnswerIPs(payload, pos, anCount)
	}

	return msg, true
}

// decodeDNSAnswerIPs walks anCount answer records starting at pos and
// returns the A-record (IPv4) addresses found.
func decodeDNSAnswerIPs(payload []byte, pos int, anCount uint16) []string {
	var ips []string

	for i := 0; i < int(anCount); i++ {
		var ok bool
		_, pos, ok = decodeDNSName(payload, pos)
		if !ok {
			break
		}

		// TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes.
		if pos+10 > len(payload) {
			break
		}
		rtype := binary.BigEndian.Uint16(payload[pos : pos+2])
		rdlen := int(binary.BigEndian.Uint16(payload[pos+8 : pos+10]))
		pos += 10

		if pos+rdlen > len(payload) {
			break
		}
		if rtype == 1 && rdlen == 4 { // A record
			ips = append(ips, net.IPv4(payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]).String())
		}
		pos += rdlen
	}

	return ips
}

// decodeDNSName decodes a (possibly compressed) domain name starting at
// pos in payload, returning the dotted name and the position immediately
// after the name in the *original* stream (i.e. after a compression
// pointer, not after whatever it points to). jumps are capped at
// dnsMaxNameJumps to guarantee termination on malformed input.
func decodeDNSName(payload []byte, pos int) (string, int, bool) {
	var sb strings.Builder
	endPos := -1
	jumps := 0

	for {
		if pos < 0 || pos >= len(payload) {
			return "", 0, false
		}

		b := payload[pos]

		if b == 0 {
			pos++
			if endPos == -1 {
				endPos = pos
			}
			break
		}

		if b&0xC0 == 0xC0 {
			if pos+1 >= len(payload) {
				return "", 0, false
			}
			if endPos == -1 {
				endPos = pos + 2
			}
			jumps++
			if jumps > dnsMaxNameJumps {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(payload[pos:pos+2]) & 0x3FFF)
			pos = ptr
			continue
		}

		labelLen := int(b)
		pos++
		if pos+labelLen > len(payload) {
			return "", 0, false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(payload[pos : pos+labelLen])
		pos += labelLen
	}

	if endPos == -1 {
		endPos = pos
	}
	return sb.String(), endPos, true
}

// intToIPv4 converts a uint32 IP in network byte order (big-endian, as stored by BPF)
// to dotted-decimal notation.
func intToIPv4(ip uint32) string {
	return net.IPv4(
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip),
	).String()
}

// qtypeToString converts DNS QTYPE to string.
func qtypeToString(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}

// rcodeToString converts DNS RCODE to string.
func rcodeToString(rcode uint16) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}
