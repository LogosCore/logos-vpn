package netstack

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// A packet's checksums sum to all ones, as a receiver checks them.
func validChecksums(t *testing.T, b []byte) packet {
	t.Helper()
	p, err := parse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.v6 && checksum(b[:20], 0) != 0 {
		t.Errorf("IPv4 header checksum")
	}
	var sum uint32
	switch p.proto {
	case protoUDP:
		sum = pseudoSum(p.src, p.dst, protoUDP, len(p.payload))
	case protoICMPv6:
		sum = pseudoSum(p.src, p.dst, protoICMPv6, len(p.payload))
	}
	if checksum(p.payload, sum) != 0 {
		t.Errorf("transport checksum of proto %d", p.proto)
	}
	return p
}

func TestUDPPacket(t *testing.T) {
	for _, c := range []struct{ from, to string }{{"10.9.0.5:53", "192.168.1.10:41000"}, {"[fd00:1::5]:53", "[fd00:2::10]:41000"}} {
		from, to := netip.MustParseAddrPort(c.from), netip.MustParseAddrPort(c.to)
		b := udpPacket(from, to, []byte("answer"))
		p := validChecksums(t, b)
		if p.src != from.Addr() || p.dst != to.Addr() || p.proto != protoUDP || !bytes.Equal(p.payload[8:], []byte("answer")) ||
			binary.BigEndian.Uint16(p.payload[0:]) != 53 || binary.BigEndian.Uint16(p.payload[2:]) != 41000 {
			t.Errorf("%s: %+v", c.from, p)
		}
	}
}

func TestEchoReplyAndErrors(t *testing.T) {
	host, me := netip.MustParseAddr("10.9.0.5"), netip.MustParseAddr("192.168.1.10")
	p := validChecksums(t, echoReply(host, me, 7, 3, []byte("ping")))
	m, err := protocol.ReadICMP(p.payload, false)
	if err != nil || m.Type != protocol.ICMPEchoReply || m.ID != 7 || m.Seq != 3 || string(m.Payload) != "ping" || p.src != host || p.dst != me {
		t.Errorf("echo reply: %+v %v", m, err)
	}
	// An unreachable quotes the packet it answers: its IP header and 8 bytes.
	syn := make([]byte, 40)
	copy(syn, ipHeader(me, host, protoTCP, 20))
	binary.BigEndian.PutUint16(syn[20:], 41000)
	binary.BigEndian.PutUint16(syn[22:], 445)
	binary.BigEndian.PutUint32(syn[24:], 0xdeadbeef)
	e := validChecksums(t, unreachableError(syn, unreachableHost))
	if e.src != host || e.dst != me || e.payload[0] != protocol.ICMPDestUnreachable || e.payload[1] != protocol.ICMPHostUnreachable ||
		!bytes.Equal(e.payload[8:], syn[:28]) {
		t.Errorf("unreachable: % x", e.payload)
	}
	// A quote kept cut short still answers.
	if e := unreachableError(syn[:28], unreachableNet); e == nil {
		t.Error("a quote cut short")
	}
	v6syn := make([]byte, 60)
	copy(v6syn, ipHeader(netip.MustParseAddr("fd00:2::10"), netip.MustParseAddr("fd00:1::5"), protoTCP, 20))
	e6 := validChecksums(t, unreachableError(v6syn, unreachableProhibited))
	if !e6.v6 || e6.proto != protoICMPv6 || e6.payload[0] != protocol.ICMPv6DestUnreachable || e6.payload[1] != protocol.ICMPv6AdminProhibited {
		t.Errorf("an IPv6 prohibited: % x", e6.payload[:8])
	}
}

func TestParseRefuses(t *testing.T) {
	frag := ipHeader(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), protoUDP, 8)
	frag = append(frag, make([]byte, 8)...)
	frag[6] = 0x20 // more fragments
	for name, b := range map[string][]byte{"empty": nil, "short": {0x45, 0}, "a fragment": frag, "version 5": {0x50, 0, 0, 0}} {
		if _, err := parse(b); err == nil {
			t.Errorf("%s parsed", name)
		}
	}
}
