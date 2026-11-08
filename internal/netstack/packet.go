// Package netstack is logos-vpn's TCP/IP stack (docs: contracts/vpn-front,
// On the machine): it reads the packets the machine routes to the client's
// interface, ends each TCP connection in a user-space stack (gVisor's), and
// hands UDP datagrams and pings to the client as they are; what comes back
// it writes to the interface as the machine would have had it.
package netstack

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// IP protocol numbers the stack reads.
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// packet is an IP packet as read: its family, protocol, addresses, where its
// transport header starts, and the whole.
type packet struct {
	v6       bool
	proto    int
	src, dst netip.Addr
	// payload is what follows the IP header (the transport's).
	payload []byte
	raw     []byte
}

var errPacket = errors.New("not an IP packet the stack reads")

// parse reads an IP packet's header: IPv4 with no fragment past the first,
// or IPv6 whose next header is the transport (no extension headers).
func parse(b []byte) (packet, error) {
	if len(b) < 1 {
		return packet{}, errPacket
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return packet{}, errPacket
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:]))
		if ihl < 20 || total < ihl || total > len(b) {
			return packet{}, errPacket
		}
		if frag := binary.BigEndian.Uint16(b[6:]); frag&0x1fff != 0 || frag&0x2000 != 0 {
			// A fragment: the stack reads whole datagrams alone.
			return packet{}, errPacket
		}
		src, _ := netip.AddrFromSlice(b[12:16])
		dst, _ := netip.AddrFromSlice(b[16:20])
		return packet{proto: int(b[9]), src: src, dst: dst, payload: b[ihl:total], raw: b[:total]}, nil
	case 6:
		if len(b) < 40 {
			return packet{}, errPacket
		}
		plen := int(binary.BigEndian.Uint16(b[4:]))
		if 40+plen > len(b) {
			return packet{}, errPacket
		}
		src, _ := netip.AddrFromSlice(b[8:24])
		dst, _ := netip.AddrFromSlice(b[24:40])
		return packet{v6: true, proto: int(b[6]), src: src, dst: dst, payload: b[40 : 40+plen], raw: b[:40+plen]}, nil
	}
	return packet{}, errPacket
}

// peek reads the addresses of a packet that may be cut short (the quote an
// ICMP error carries): its family, source and destination.
func peek(b []byte) (v6 bool, src, dst netip.Addr, ok bool) {
	switch {
	case len(b) >= 20 && b[0]>>4 == 4:
		src, _ = netip.AddrFromSlice(b[12:16])
		dst, _ = netip.AddrFromSlice(b[16:20])
		return false, src, dst, true
	case len(b) >= 40 && b[0]>>4 == 6:
		src, _ = netip.AddrFromSlice(b[8:24])
		dst, _ = netip.AddrFromSlice(b[24:40])
		return true, src, dst, true
	}
	return false, netip.Addr{}, netip.Addr{}, false
}

// ipHeader writes an IP header for a payload of n bytes, from src to dst.
func ipHeader(src, dst netip.Addr, proto, n int) []byte {
	if src.Is4() {
		h := make([]byte, 20, 20+n)
		h[0], h[8], h[9] = 0x45, 64, byte(proto)
		binary.BigEndian.PutUint16(h[2:], uint16(20+n))
		s, d := src.As4(), dst.As4()
		copy(h[12:], s[:])
		copy(h[16:], d[:])
		binary.BigEndian.PutUint16(h[10:], protocol.ICMPChecksum(h))
		return h
	}
	h := make([]byte, 40, 40+n)
	h[0], h[6], h[7] = 0x60, byte(proto), 64
	binary.BigEndian.PutUint16(h[4:], uint16(n))
	s, d := src.As16(), dst.As16()
	copy(h[8:], s[:])
	copy(h[24:], d[:])
	return h
}

// pseudoSum is the sum of a transport checksum's pseudo-header.
func pseudoSum(src, dst netip.Addr, proto, n int) uint32 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
	}
	add(src.AsSlice())
	add(dst.AsSlice())
	sum += uint32(proto) + uint32(n)
	return sum
}

// checksum is the Internet checksum of b, with the sum so far.
func checksum(b []byte, sum uint32) uint16 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// udpPacket is a UDP datagram from src to dst, as an IP packet.
func udpPacket(src, dst netip.AddrPort, payload []byte) []byte {
	n := 8 + len(payload)
	h := ipHeader(src.Addr(), dst.Addr(), protoUDP, n)
	u := make([]byte, 8, n)
	binary.BigEndian.PutUint16(u[0:], src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(n))
	u = append(u, payload...)
	c := checksum(u, pseudoSum(src.Addr(), dst.Addr(), protoUDP, n))
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], c)
	return append(h, u...)
}

// icmpPacket is an ICMP message (from its type on, its checksum filled in
// here) from src to dst, as an IP packet: ICMPv6's checksum covers the
// pseudo-header, IPv4's does not.
func icmpPacket(src, dst netip.Addr, msg []byte) []byte {
	m := append([]byte(nil), msg...)
	m[2], m[3] = 0, 0
	proto := protoICMP
	var sum uint32
	if !src.Is4() {
		proto = protoICMPv6
		sum = pseudoSum(src, dst, protoICMPv6, len(m))
	}
	binary.BigEndian.PutUint16(m[2:], checksum(m, sum))
	return append(ipHeader(src, dst, proto, len(m)), m...)
}

// echoReply is an echo reply from src to dst, its identifier and sequence
// the request's.
func echoReply(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	_, reply := protocol.ICMPEchoTypes(!src.Is4())
	return icmpPacket(src, dst, protocol.ICMPMessage{Type: reply, ID: id, Seq: seq, Payload: payload}.Bytes(!src.Is4()))
}

// quoteLen is how much of a packet an ICMP error quotes: its IP header and
// 8 bytes past it (IPv4's rule), at most what keeps IPv6's within 1280.
func quoteLen(orig []byte) int {
	if len(orig) > 0 && orig[0]>>4 == 6 {
		return min(len(orig), 1280-40-8)
	}
	ihl := 20
	if len(orig) > 0 {
		ihl = int(orig[0]&0x0f) * 4
	}
	return min(len(orig), ihl+8)
}

// icmpError is an ICMP error (unreachable, time exceeded, prohibited) from
// from to the original packet's source, quoting it.
func icmpError(from netip.Addr, orig []byte, typ, code int) []byte {
	v6, src, dst, ok := peek(orig)
	if !ok {
		return nil
	}
	if from = from.Unmap(); !from.IsValid() || from.Is4() == v6 {
		from = dst
	}
	msg := make([]byte, 8, 8+quoteLen(orig))
	msg[0], msg[1] = byte(typ), byte(code)
	msg = append(msg, orig[:quoteLen(orig)]...)
	return icmpPacket(from, src, msg)
}

// Unreachable codes, by what a minion's result says (IPv4's, IPv6's).
type unreachable int

const (
	unreachableHost unreachable = iota
	unreachableNet
	unreachableProhibited
)

// unreachableError is the ICMP error that says a destination is
// unreachable, or communication with it administratively prohibited.
func unreachableError(orig []byte, why unreachable) []byte {
	v6, _, dst, ok := peek(orig)
	if !ok {
		return nil
	}
	if v6 {
		code := map[unreachable]int{unreachableHost: protocol.ICMPv6AddrUnreachable, unreachableNet: protocol.ICMPv6NoRoute,
			unreachableProhibited: protocol.ICMPv6AdminProhibited}[why]
		return icmpError(dst, orig, protocol.ICMPv6DestUnreachable, code)
	}
	code := map[unreachable]int{unreachableHost: protocol.ICMPHostUnreachable, unreachableNet: protocol.ICMPNetUnreachable,
		unreachableProhibited: protocol.ICMPAdminProhibited}[why]
	return icmpError(dst, orig, protocol.ICMPDestUnreachable, code)
}
