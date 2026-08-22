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
// timestamp(8) + pid(4) + tgid(4) + uid(4) + comm(16) + ppid(4) +
// parent_comm(16) + direction(1) + payload_len(2) = 63. The struct is
// packed, so there is no padding. ppid/parent_comm added by plan.md 5.9.4i
// (debt from 5.9.3d) so DNS-triggered alerts carry a process_chain.
const dnsRawEventFixedLen = 4 + 8 + 4 + 4 + 4 + 16 + 4 + 16 + 1 + 2

// dnsMaxPayload mirrors DNS_MAX_PAYLOAD in dns.bpf.c — the kernel side
// always reserves this many payload bytes in the ring buffer record,
// truncating longer messages rather than dropping them.
const dnsMaxPayload = 256

// dnsMaxNameJumps bounds compression-pointer chasing in decodeDNSName so a
// crafted or corrupted message can't cause an infinite loop. There is no
// BPF verifier here — this is a plain userspace safety limit.
const dnsMaxNameJumps = 32

// DNS decode-failure reasons, published on ebpf_guard_dns_decode_errors_total
// (wave 5.9.5c, findings №64/№65). Kept as a closed vocabulary — a new failure
// mode should map onto one of these or add one deliberately, not fall through
// to "unparseable" by accident:
//
//	too_short          — record (or the DNS payload within it) is smaller than
//	                      the fixed header it must contain.
//	not_a_query        — well-formed header, but QDCOUNT=0: not a request or
//	                      response to any question, so there is nothing to
//	                      correlate against a rule.
//	bad_qname          — a label or pointer in a name walk points outside the
//	                      buffer or claims a length the buffer doesn't have.
//	truncated_payload  — payload_len from the BPF side exceeds DNS_MAX_PAYLOAD
//	                      or the bytes actually present in the record.
//	compression_loop    — name compression pointers exceeded dnsMaxNameJumps.
//	bad_header         — well-formed length, but the fixed 12-byte DNS header
//	                      fails a structural sanity check (reserved Z bit set,
//	                      or opcode outside the IANA range — see
//	                      validateDNSHeader for why section-length
//	                      consistency is deliberately not checked here): the
//	                      bytes are not a DNS message at all, most likely
//	                      non-DNS traffic that reached this path because
//	                      dns_socket_map misclassified an fd (plan.md 5.9.8a,
//	                      №94 — a TLS ClientHello read via a reused fd number
//	                      previously reached parseDNSWireMessage and was
//	                      scored against the long-label rules as if it were a
//	                      QNAME).
//	unparseable        — caught a failure this vocabulary doesn't name yet
//	                      (event type mismatch on the DNS-only ring buffer, or
//	                      any future branch that doesn't set a reason).
const (
	dnsDecodeReasonTooShort         = "too_short"
	dnsDecodeReasonNotAQuery        = "not_a_query"
	dnsDecodeReasonBadQName         = "bad_qname"
	dnsDecodeReasonTruncatedPayload = "truncated_payload"
	dnsDecodeReasonCompressionLoop  = "compression_loop"
	dnsDecodeReasonBadHeader        = "bad_header"
	dnsDecodeReasonUnparseable      = "unparseable"
)

// dnsDecodeReasons is the closed vocabulary above as a list, so the collector
// can prime one metric series and one rate-limited logger per reason without
// either place re-deriving the set (and drifting from it).
var dnsDecodeReasons = []string{
	dnsDecodeReasonTooShort,
	dnsDecodeReasonNotAQuery,
	dnsDecodeReasonBadQName,
	dnsDecodeReasonTruncatedPayload,
	dnsDecodeReasonCompressionLoop,
	dnsDecodeReasonBadHeader,
	dnsDecodeReasonUnparseable,
}

// dnsMaxOpcode is the highest IANA-assigned DNS OPCODE as of this writing
// (6 = DSO, RFC 8490). Anything above it is not a value any real resolver or
// server emits, and is exactly the kind of bit pattern non-DNS traffic
// (a TLS record header, in particular) produces by coincidence.
const dnsMaxOpcode = 6

// validateDNSHeader is the second, independent guard against non-DNS bytes
// reaching the QNAME walk, on top of the dns_socket_map key fix in
// dns.bpf.c (plan.md 5.9.8a, №94, запрет №6: the kernel-side fix and this
// check are both required on the same run, not either/or). Even a perfectly
// fd-scoped dns_socket_map only proves the fd was once connect()ed to
// port 53 — it says nothing about what bytes a later write()/read() on that
// fd actually carries, so this checks the bytes themselves against the
// structural constraints RFC 1035 places on a DNS header, before a single
// label byte is walked:
//
//   - the Z bit (RFC 1035 §4.1.1, reserved, must be zero in every
//     conforming message) is set — real resolvers and servers never set it;
//   - OPCODE is outside the range any assigned value occupies.
//
// Section-length consistency (payload_len vs the sum of header+question+
// answers) is deliberately NOT re-checked here: decodeDNSName/
// decodeDNSAnswerIPs already reject a name or record that overruns the
// buffer as dnsDecodeReasonBadQName, and decodeDNSEvent already rejects a
// payload_len inconsistent with the record itself as
// dnsDecodeReasonTruncatedPayload — duplicating either check here with a
// coarser rule of thumb would only produce a second, less accurate opinion
// about the same bytes (and did, in an earlier revision of this function: a
// QDCOUNT-vs-length budget check misclassified a legitimately truncated
// question as bad_header instead of letting the qname walk call it
// bad_qname, see TestParseDNSWireMessage_BadQName).
//
// This is a guard, not a classifier: a TLS ClientHello read off a reused fd
// lands its record-length bytes in the position a DNS header keeps its flags,
// so whether it trips one of these two checks depends on that length — a
// ClientHello of 0x003b bytes yields opcode=0 and a clear Z bit and passes
// here, then fails downstream in decodeDNSName as bad_qname. Both outcomes
// are correct and both are non-events for the long-label rules; what matters
// is the invariant that no such message ever becomes a DNS event, which is
// what TestParseDNSWireMessage_TLSClientHelloNeverAccepted pins (and why it
// asserts on the invariant rather than on bad_header specifically).
func validateDNSHeader(payload []byte) string {
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x0040 != 0 { // Z bit, RFC 1035 §4.1.1
		return dnsDecodeReasonBadHeader
	}
	opcode := (flags >> 11) & 0x0f
	if opcode > dnsMaxOpcode {
		return dnsDecodeReasonBadHeader
	}
	return ""
}

// dnsHeaderDiagFields reads direction and payload_len straight out of the
// fixed dns_event header, independent of whether decodeDNSEvent went on to
// parse the wire message successfully. 5.9.6g (№65): the three decode-error
// hypotheses from 5.9.5c — a response captured with the wrong assumption
// about which side is which, a non-UDP/53 message reaching the parser
// (TCP-DNS/mDNS), and truncation at DNS_MAX_PAYLOAD — are exactly the three
// things these two fields distinguish. bad_qname/compression_loop on a
// direction=1 (response) with payload_len at or near dnsMaxPayload usually
// means hypothesis 3; the same reason on a small payload_len rules 3 out and
// points at 1 or 2 instead. ok is false when raw is too short for even the
// fixed header (too_short/unparseable already cover that case; the caller
// doesn't log these fields there because there is nothing reliable to read).
func dnsHeaderDiagFields(raw []byte) (direction byte, payloadLen uint16, ok bool) {
	if len(raw) < dnsRawEventFixedLen {
		return 0, 0, false
	}
	direction = raw[dnsRawEventFixedLen-3]
	payloadLen = binary.LittleEndian.Uint16(raw[dnsRawEventFixedLen-2:])
	return direction, payloadLen, true
}

// decodeDNSEvent parses a raw ring buffer record into a types.Event. It has no
// kernel dependencies — it only decodes bytes — so it is unit-tested directly
// without a running probe.
//
// The BPF side (dns.bpf.c) no longer decodes the DNS wire format — it just
// captures the raw UDP payload, so all QNAME/QTYPE/RCODE/answer parsing,
// including compression-pointer chasing, happens here where there's no
// verifier instruction budget to fight. A nil event means the record is not a
// usable DNS event; the second return is always "" on success and one of the
// dnsDecodeReason* constants on failure, so the caller can attribute the drop
// instead of only counting it (5.9.5c).
func decodeDNSEvent(raw []byte) (*types.Event, string) {
	if len(raw) < dnsRawEventFixedLen {
		return nil, dnsDecodeReasonTooShort
	}

	// Parse the fixed dns_event header. Layout matches struct dns_event in
	// dns.bpf.c.
	offset := 0

	// type (4 bytes)
	eventType := binary.LittleEndian.Uint32(raw[offset:])
	offset += 4

	if eventType != uint32(types.EventDNS) {
		return nil, dnsDecodeReasonUnparseable
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

	// ppid (4 bytes)
	ppid := binary.LittleEndian.Uint32(raw[offset:])
	offset += 4

	// parent_comm (16 bytes)
	var parentComm [16]byte
	copy(parentComm[:], raw[offset:])
	offset += 16

	// direction (1 byte)
	direction := types.DNSDirection(raw[offset])
	offset += 1

	// payload_len (2 bytes)
	payloadLen := binary.LittleEndian.Uint16(raw[offset:])
	offset += 2

	if int(payloadLen) > dnsMaxPayload || offset+int(payloadLen) > len(raw) {
		return nil, dnsDecodeReasonTruncatedPayload
	}
	payload := raw[offset : offset+int(payloadLen)]

	msg, reason := parseDNSWireMessage(payload)
	if reason != "" {
		return nil, reason
	}

	return &types.Event{
		Type:       types.EventDNS,
		Timestamp:  types.KtimeToEpoch(timestamp),
		PID:        pid,
		TGID:       tgid,
		PPID:       ppid,
		UID:        uid,
		Comm:       comm,
		ParentComm: parentComm,
		DNS: &types.DNSEvent{
			QName:       msg.qname,
			QType:       msg.qtype,
			RCode:       msg.rcode,
			Direction:   direction,
			ResponseIPs: msg.responseIPs,
		},
	}, ""
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
func parseDNSWireMessage(payload []byte) (dnsWireMessage, string) {
	var msg dnsWireMessage

	if len(payload) < 12 {
		return msg, dnsDecodeReasonTooShort
	}

	// Second, independent guard (plan.md 5.9.8a, запрет №6): reject bytes
	// that fail basic DNS header structure before touching a single label —
	// this is what stops a TLS ClientHello read via a reused fd number from
	// scoring against the long-label rules even if dns_socket_map ever
	// misclassifies an fd again in the future.
	if reason := validateDNSHeader(payload); reason != "" {
		return msg, reason
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	isResponse := flags&0x8000 != 0
	msg.rcode = flags & 0x000f

	qdCount := binary.BigEndian.Uint16(payload[4:6])
	anCount := binary.BigEndian.Uint16(payload[6:8])
	if qdCount == 0 {
		return msg, dnsDecodeReasonNotAQuery
	}

	pos := 12
	qname, pos, reason := decodeDNSName(payload, pos)
	if reason != "" {
		return msg, reason
	}
	msg.qname = qname

	if pos+4 > len(payload) {
		// Got the name but not QTYPE/QCLASS; still useful to the caller.
		return msg, ""
	}
	msg.qtype = binary.BigEndian.Uint16(payload[pos : pos+2])
	pos += 4 // QTYPE (2) + QCLASS (2)

	if isResponse {
		msg.responseIPs = decodeDNSAnswerIPs(payload, pos, anCount)
	}

	return msg, ""
}

// decodeDNSAnswerIPs walks anCount answer records starting at pos and
// returns the A-record (IPv4) addresses found. A malformed answer name or
// record stops the walk (returning whatever IPs were found so far) rather
// than failing the whole message — the question section already parsed
// cleanly, and this loop's own failure reason is not surfaced to
// dns_decode_errors_total, only the top-level parse failure is.
func decodeDNSAnswerIPs(payload []byte, pos int, anCount uint16) []string {
	var ips []string

	for i := 0; i < int(anCount); i++ {
		var reason string
		_, pos, reason = decodeDNSName(payload, pos)
		if reason != "" {
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
func decodeDNSName(payload []byte, pos int) (string, int, string) {
	var sb strings.Builder
	endPos := -1
	jumps := 0

	for {
		if pos < 0 || pos >= len(payload) {
			return "", 0, dnsDecodeReasonBadQName
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
				return "", 0, dnsDecodeReasonBadQName
			}
			if endPos == -1 {
				endPos = pos + 2
			}
			jumps++
			if jumps > dnsMaxNameJumps {
				return "", 0, dnsDecodeReasonCompressionLoop
			}
			ptr := int(binary.BigEndian.Uint16(payload[pos:pos+2]) & 0x3FFF)
			pos = ptr
			continue
		}

		labelLen := int(b)
		pos++
		if pos+labelLen > len(payload) {
			return "", 0, dnsDecodeReasonBadQName
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
	return sb.String(), endPos, ""
}

// intToIPv4 converts a uint32 IP in network byte order (big-endian, as stored by BPF)
// to dotted-decimal notation.
func intToIPv4(ip uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ip)
	return net.IP(b[:]).String()
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
