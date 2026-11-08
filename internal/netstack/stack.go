package netstack

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Device is the client's interface: packets read and written whole, from
// offset in each buffer (wireguard-go's tun.Device).
type Device interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
	BatchSize() int
}

// Handler is what carries the machine's flows: the client's streams over
// its link to core.
type Handler interface {
	// TCP opens a stream to dst for the machine's connection from src,
	// waiting for the minion's answer: its result (protocol.TunnelOpen,
	// ...), and the stream when it opened.
	TCP(src, dst netip.AddrPort) (TCPStream, int)
	// UDP sends the machine's datagram from src to dst: false when the
	// tunnel carries no UDP (its command opens none).
	UDP(src, dst netip.AddrPort, payload []byte) bool
	// Ping sends the machine's echo request from src to dst (orig: the
	// packet it came in): false when the tunnel carries no pings.
	Ping(src, dst netip.Addr, echo protocol.ICMPMessage, orig []byte) bool
	// Routed says whether dst is in the tunnel's routes.
	Routed(dst netip.Addr) bool
}

// TCPStream carries a connection the stack ended, once it opened.
type TCPStream interface {
	Run(c *Conn)
}

// Conn is a connection of the machine's, ended in the stack: its bytes
// both ways, a half close, and an abort (a reset).
type Conn struct {
	*gonet.TCPConn
	ep tcpip.Endpoint
}

// Abort resets the connection.
func (c *Conn) Abort() { c.ep.Abort() }

const (
	nicID = 1
	// offset is where a packet starts in a device's buffer: room for a
	// device's own header (wireguard-go's: Linux's virtio header, the
	// macOS family word).
	offset = 16
	// maxPacket is the most a read takes: a device that coalesces segments
	// splits them into its MTU.
	maxPacket = 1<<16 - 1
	// synKept is how long a SYN's packet is kept, to quote in the ICMP
	// error that answers it; synsKept how many at most.
	synKept  = 3 * time.Minute
	synsKept = 1 << 14
	// maxPending is how many connections may wait for the minion at once.
	maxPending = 1 << 14
)

// Stack is the client's TCP/IP stack over its device.
type Stack struct {
	dev     Device
	h       Handler
	mtu     int
	s       *stack.Stack
	ep      *channel.Endpoint
	ctx     context.Context
	cancel  context.CancelFunc
	wmu     sync.Mutex
	wbuf    []byte
	synMu   sync.Mutex
	syns    map[[2]netip.AddrPort]synPacket
	done    sync.WaitGroup
	readErr chan error
}

type synPacket struct {
	raw []byte
	at  time.Time
}

// New is a stack over dev, carrying its flows by h. Run starts it.
func New(dev Device, mtu int, h Handler) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	ep := channel.New(1024, uint32(mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, errors.New(err.String())
	}
	// Every address routed here is the stack's: it ends connections to
	// any of them, and answers from them.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, errors.New(err.String())
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, errors.New(err.String())
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}, {Destination: header.IPv6EmptySubnet, NIC: nicID}})
	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	ctx, cancel := context.WithCancel(context.Background())
	st := &Stack{dev: dev, h: h, mtu: mtu, s: s, ep: ep, ctx: ctx, cancel: cancel, wbuf: make([]byte, offset+maxPacket),
		syns: map[[2]netip.AddrPort]synPacket{}, readErr: make(chan error, 1)}
	fwd := tcp.NewForwarder(s, 0, maxPending, st.forward)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		// A SYN opens a connection; any other packet of no connection the
		// stack drops, unanswered: a reset of its own would make every
		// address look alive (nmap's ACK ping).
		flags := header.TCP(pkt.TransportHeader().Slice()).Flags()
		if flags.Contains(header.TCPFlagSyn) && !flags.Contains(header.TCPFlagAck) {
			return fwd.HandlePacket(id, pkt)
		}
		return true
	})
	return st, nil
}

// Run carries packets both ways until Close, or the device fails (its
// error comes on Err).
func (st *Stack) Run() {
	st.done.Add(2)
	go st.read()
	go st.write()
}

// Err is the device's read error, once it failed.
func (st *Stack) Err() <-chan error { return st.readErr }

// Close stops the stack: its connections close.
func (st *Stack) Close() {
	st.cancel()
	st.s.Close()
	st.ep.Close()
}

// read takes the device's packets: TCP into the stack, UDP and pings to
// the handler; anything else, or to an address not routed, is dropped.
func (st *Stack) read() {
	defer st.done.Done()
	batch := max(st.dev.BatchSize(), 1)
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, offset+maxPacket)
	}
	sizes := make([]int, batch)
	for {
		n, err := st.dev.Read(bufs, sizes, offset)
		for i := range n {
			st.take(bufs[i][offset : offset+sizes[i]])
		}
		if err != nil {
			if st.ctx.Err() == nil && !errors.Is(err, io.EOF) {
				st.readErr <- err
			}
			return
		}
	}
}

// take is one packet of the machine's.
func (st *Stack) take(b []byte) {
	p, err := parse(b)
	if err != nil || !st.h.Routed(p.dst) {
		return
	}
	switch p.proto {
	case protoTCP:
		if len(p.payload) >= header.TCPMinimumSize {
			flags := header.TCP(p.payload).Flags()
			if flags.Contains(header.TCPFlagSyn) && !flags.Contains(header.TCPFlagAck) {
				st.keepSYN(p)
			}
		}
		proto := ipv4.ProtocolNumber
		if p.v6 {
			proto = ipv6.ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), p.raw...))})
		st.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	case protoUDP:
		if len(p.payload) < 8 {
			return
		}
		sport, dport := uint16(p.payload[0])<<8|uint16(p.payload[1]), uint16(p.payload[2])<<8|uint16(p.payload[3])
		if !st.h.UDP(netip.AddrPortFrom(p.src, sport), netip.AddrPortFrom(p.dst, dport), append([]byte(nil), p.payload[8:]...)) {
			st.WritePacket(unreachableError(p.raw, unreachableProhibited))
		}
	case protoICMP, protoICMPv6:
		if (p.proto == protoICMPv6) != p.v6 {
			return
		}
		m, err := protocol.ReadICMP(p.payload, p.v6)
		req, _ := protocol.ICMPEchoTypes(p.v6)
		if err != nil || m.Type != req {
			// Echo requests alone go: the machine's own errors and replies
			// have no one here to go to.
			return
		}
		if !st.h.Ping(p.src, p.dst, m, append([]byte(nil), p.raw...)) {
			st.WritePacket(unreachableError(p.raw, unreachableProhibited))
		}
	}
}

// keepSYN keeps a SYN's packet, to quote should its answer be an ICMP
// error.
func (st *Stack) keepSYN(p packet) {
	sport := uint16(p.payload[0])<<8 | uint16(p.payload[1])
	dport := uint16(p.payload[2])<<8 | uint16(p.payload[3])
	key := [2]netip.AddrPort{netip.AddrPortFrom(p.src, sport), netip.AddrPortFrom(p.dst, dport)}
	now := time.Now()
	st.synMu.Lock()
	defer st.synMu.Unlock()
	if len(st.syns) >= synsKept {
		for k, v := range st.syns {
			if now.Sub(v.at) > synKept {
				delete(st.syns, k)
			}
		}
		if len(st.syns) >= synsKept {
			return
		}
	}
	st.syns[key] = synPacket{raw: append([]byte(nil), p.raw[:min(len(p.raw), quoteLen(p.raw))]...), at: now}
}

// syn is the kept SYN of a connection from src to dst, forgotten.
func (st *Stack) syn(src, dst netip.AddrPort) []byte {
	key := [2]netip.AddrPort{src, dst}
	st.synMu.Lock()
	defer st.synMu.Unlock()
	p := st.syns[key]
	delete(st.syns, key)
	return p.raw
}

// forward is a SYN of the machine's: a stream to its destination, the
// handshake completed only once the minion opened it; else answered as
// the minion's host would have.
func (st *Stack) forward(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)
	src := netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort)
	stream, result := st.h.TCP(src, dst)
	syn := st.syn(src, dst)
	switch result {
	case protocol.TunnelOpen:
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		go stream.Run(&Conn{TCPConn: gonet.NewTCPConn(&wq, ep), ep: ep})
	case protocol.TunnelHostUnreachable, protocol.TunnelNetUnreachable, protocol.TunnelDenied:
		r.Complete(false)
		why := map[int]unreachable{protocol.TunnelHostUnreachable: unreachableHost, protocol.TunnelNetUnreachable: unreachableNet,
			protocol.TunnelDenied: unreachableProhibited}[result]
		if syn != nil {
			st.WritePacket(unreachableError(syn, why))
		}
	case protocol.TunnelTimedOut, protocol.TunnelNotAllowed:
		// Unanswered, as a filtered port's SYN: the machine sends it again.
		r.Complete(false)
	default:
		// Refused, failed, unsupported, or a result not known: a reset.
		r.Complete(true)
	}
}

func addrOf(a tcpip.Address) netip.Addr {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return ip
}

// write writes the stack's packets to the device.
func (st *Stack) write() {
	defer st.done.Done()
	for {
		pkt := st.ep.ReadContext(st.ctx)
		if pkt == nil {
			return
		}
		var b []byte
		for _, s := range pkt.AsSlices() {
			b = append(b, s...)
		}
		pkt.DecRef()
		st.WritePacket(b)
	}
}

// WritePacket writes an IP packet to the device, as the machine's from the
// minion's networks (nil: nothing).
func (st *Stack) WritePacket(b []byte) {
	if len(b) == 0 || len(b) > maxPacket {
		return
	}
	st.wmu.Lock()
	defer st.wmu.Unlock()
	buf := st.wbuf[:offset+len(b)]
	copy(buf[offset:], b)
	_, _ = st.dev.Write([][]byte{buf}, offset)
}

// WriteUDP writes a datagram from a host in the minion's networks to the
// machine.
func (st *Stack) WriteUDP(from, to netip.AddrPort, payload []byte) {
	st.WritePacket(udpPacket(from, to, payload))
}

// WriteEchoReply writes an echo reply from a host to the machine, its
// identifier and sequence the machine's.
func (st *Stack) WriteEchoReply(from, to netip.Addr, id, seq uint16, payload []byte) {
	st.WritePacket(echoReply(from, to, id, seq, payload))
}

// WriteICMPError writes an ICMP error from a host or a router (from) about
// a packet of the machine's (orig).
func (st *Stack) WriteICMPError(from netip.Addr, orig []byte, typ, code int) {
	st.WritePacket(icmpError(from, orig, typ, code))
}
