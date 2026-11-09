package client_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-vpn/internal/client"
	"github.com/logoscore/logos-vpn/internal/netstack"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// The machine is a stack of its own (gVisor's, playing the operator's
// system) whose route to 10.9.0.0/24 is the client's device: what it sends
// there the client's stack reads, and what the client's stack writes it
// receives. Core is the test, over the client's frames.

// device is the client's interface in memory.
type device struct {
	toClient chan []byte
	machine  *channel.Endpoint
	written  chan []byte
	closed   chan struct{}
}

func (d *device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-d.toClient:
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *device) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		p := append([]byte(nil), b[offset:]...)
		select {
		case d.written <- p:
		default:
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
		d.machine.InjectInbound(ipv4.ProtocolNumber, pkt)
		pkt.DecRef()
	}
	return len(bufs), nil
}

func (d *device) BatchSize() int { return 1 }

var machineAddr = tcpip.AddrFrom4([4]byte{192, 168, 50, 2})

// newMachine is the machine's stack, its packets to the device.
func newMachine(t *testing.T, d *device) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	ep := channel.New(1024, 1500, "")
	d.machine = ep
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: machineAddr.WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); s.Close() })
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			var b []byte
			for _, sl := range pkt.AsSlices() {
				b = append(b, sl...)
			}
			pkt.DecRef()
			select {
			case d.toClient <- b:
			case <-ctx.Done():
				return
			}
		}
	}()
	return s
}

// fakeCore answers the client's frames as core does: each host by
// result, bytes echoed back, datagrams answered.
type fakeCore struct {
	t      *testing.T
	c      *client.Client
	task   []byte
	result map[string]int
	mu     sync.Mutex
	opens  []protocol.TunnelItem
	got    map[uint64][]byte
	next   map[uint64]uint64
	eof    map[uint64]bool
	sent   map[uint64]uint64
	closes map[uint64]int
	dgrams []protocol.TunnelDatagramItem
	stop   chan struct{}
}

func (f *fakeCore) run() {
	for {
		select {
		case <-f.stop:
			return
		case <-f.c.Kick():
		case <-time.After(20 * time.Millisecond):
		}
		for {
			frame, more := f.c.NextFrame()
			if frame != nil {
				f.take(frame)
			}
			if !more {
				break
			}
		}
	}
}

func marshal(v any) cbor.RawMessage {
	b, _ := protocol.MarshalCBOR(v)
	return b
}

func (f *fakeCore) take(frame []byte) {
	items, err := protocol.ReadVPNFrame(frame)
	if err != nil {
		f.t.Errorf("a frame: %v", err)
		return
	}
	var out []cbor.RawMessage
	f.mu.Lock()
	for _, raw := range items {
		switch protocol.ItemType(raw) {
		case protocol.ItemTunnel:
			it, err := protocol.ReadTunnel(raw)
			if err != nil {
				f.t.Errorf("an open: %v", err)
				continue
			}
			f.opens = append(f.opens, it)
			result := f.result[it.Host]
			out = append(out, marshal(protocol.TunnelReplyItem{T: protocol.ItemTunnelReply, Task: f.task, Stream: it.Stream, Result: result}))
		case protocol.ItemTunnelData:
			var d protocol.TunnelDataItem
			_ = protocol.UnmarshalCBOR(raw, &d)
			if d.Off == f.next[d.Stream] && !f.eof[d.Stream] {
				f.got[d.Stream] = append(f.got[d.Stream], d.Data...)
				f.next[d.Stream] += uint64(len(d.Data))
				// Echoed back, with the eof when it comes.
				echo := protocol.TunnelDataItem{T: protocol.ItemTunnelData, Task: f.task, Stream: d.Stream, Off: f.sent[d.Stream],
					Data: append([]byte(nil), d.Data...), EOF: d.EOF}
				f.sent[d.Stream] = echo.End()
				if d.EOF {
					f.eof[d.Stream] = true
					f.next[d.Stream]++
				}
				out = append(out, marshal(echo))
			}
			out = append(out, marshal(protocol.TunnelAckItem{T: protocol.ItemTunnelAck, Task: f.task, Stream: d.Stream, Next: f.next[d.Stream]}))
		case protocol.ItemTunnelClose:
			var cl protocol.TunnelCloseItem
			_ = protocol.UnmarshalCBOR(raw, &cl)
			f.closes[cl.Stream] = cl.Reason
		case protocol.ItemTunnelDatagram:
			var d protocol.TunnelDatagramItem
			_ = protocol.UnmarshalCBOR(raw, &d)
			f.dgrams = append(f.dgrams, d)
			back := protocol.TunnelDatagramItem{T: protocol.ItemTunnelDatagram, Task: f.task, Stream: d.Stream, Seq: d.Seq, Host: d.Host, Port: d.Port,
				Data: append([]byte("re: "), d.Data...)}
			if d.Port == 0 {
				// A ping: its host answers its echo.
				m, _ := protocol.ReadICMP(d.Data, false)
				back.Data = protocol.ICMPMessage{Type: protocol.ICMPEchoReply, ID: 99, Seq: m.Seq, Payload: m.Payload}.Bytes(false)
			}
			out = append(out, marshal(back))
		}
	}
	f.mu.Unlock()
	if len(out) > 0 {
		b, err := protocol.VPNFrame(out)
		if err != nil {
			f.t.Error(err)
			return
		}
		if err := f.c.Take(b); err != nil {
			f.t.Error(err)
		}
	}
}

type rig struct {
	machine *stack.Stack
	core    *fakeCore
	dev     *device
	st      *netstack.Stack
	c       *client.Client
}

func newRig(t *testing.T, opens []string, results map[string]int) *rig {
	t.Helper()
	task := uuid.New()
	c, err := client.New(protocol.VPNWelcome{Task: task.String(), Routes: []string{"10.9.0.0/24"}, MaxStreams: 256, Opens: opens})
	if err != nil {
		t.Fatal(err)
	}
	d := &device{toClient: make(chan []byte, 1024), written: make(chan []byte, 1024), closed: make(chan struct{})}
	m := newMachine(t, d)
	st, err := netstack.New(d, 1500, c)
	if err != nil {
		t.Fatal(err)
	}
	c.SetWriter(st)
	st.Run()
	f := &fakeCore{t: t, c: c, task: task[:], result: results, got: map[uint64][]byte{}, next: map[uint64]uint64{}, eof: map[uint64]bool{},
		sent: map[uint64]uint64{}, closes: map[uint64]int{}, stop: make(chan struct{})}
	go f.run()
	t.Cleanup(func() { close(f.stop); close(d.closed); st.Close(); c.End() })
	return &rig{machine: m, core: f, dev: d, st: st, c: c}
}

func addr(s string) tcpip.FullAddress {
	ap := netip.MustParseAddrPort(s)
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ap.Addr().As4()), Port: ap.Port()}
}

// A connection of the machine's to a routed host is a stream: its
// handshake completes once core said open, its bytes go both ways, and
// both ends close done.
func TestTCPStream(t *testing.T) {
	r := newRig(t, []string{"tcp"}, map[string]int{"10.9.0.5": protocol.TunnelOpen})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, r.machine, addr("10.9.0.5:445"), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sent := bytes.Repeat([]byte("through the minion "), 50000)
	go func() {
		_, _ = conn.Write(sent)
		_ = conn.CloseWrite()
	}()
	// A deadline, not a speed: under -race on a CI runner 950 KB took past
	// 10 s once.
	_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, sent) {
		t.Fatalf("echoed %d of %d bytes: %v", len(got), len(sent), err)
	}
	_ = conn.Close()
	r.core.mu.Lock()
	open := r.core.opens[0]
	r.core.mu.Unlock()
	if open.Host != "10.9.0.5" || open.Port != 445 || open.UDP || open.Kind != 0 {
		t.Errorf("the open: %+v", open)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.core.mu.Lock()
		reason, ok := r.core.closes[open.Stream]
		r.core.mu.Unlock()
		if ok && reason == protocol.TunnelCloseDone && r.c.Streams() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the stream's close: %v %d, %d streams", ok, reason, r.c.Streams())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// What the minion's host says is what the machine sees: a refused
// connect is a reset at once, a timed out one no answer at all.
func TestTCPAnswers(t *testing.T) {
	r := newRig(t, []string{"tcp"}, map[string]int{"10.9.0.6": protocol.TunnelRefused, "10.9.0.7": protocol.TunnelTimedOut,
		"10.9.0.8": protocol.TunnelHostUnreachable})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := gonet.DialContextTCP(ctx, r.machine, addr("10.9.0.6:22"), ipv4.ProtocolNumber); err == nil ||
		!strings.Contains(err.Error(), "refused") || time.Since(start) > 2*time.Second {
		t.Errorf("refused: %v after %s", err, time.Since(start))
	}
	short, cancel2 := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel2()
	if _, err := gonet.DialContextTCP(short, r.machine, addr("10.9.0.7:22"), ipv4.ProtocolNumber); err == nil ||
		!errors.Is(short.Err(), context.DeadlineExceeded) {
		t.Errorf("timed out: %v", err)
	}
	// Host unreachable: an ICMP error quoting the machine's SYN.
	short3, cancel3 := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel3()
	drain(r.dev.written)
	_, _ = gonet.DialContextTCP(short3, r.machine, addr("10.9.0.8:22"), ipv4.ProtocolNumber)
	if !sawICMP(r.dev.written, protocol.ICMPDestUnreachable, protocol.ICMPHostUnreachable) {
		t.Error("no ICMP host unreachable")
	}
	// Outside the routes: nothing opens.
	r.core.mu.Lock()
	for _, o := range r.core.opens {
		if !strings.HasPrefix(o.Host, "10.9.0.") {
			t.Errorf("an open outside the routes: %+v", o)
		}
	}
	r.core.mu.Unlock()
}

func drain(ch chan []byte) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func sawICMP(ch chan []byte, typ, code int) bool {
	deadline := time.After(2 * time.Second)
	for {
		select {
		case p := <-ch:
			if len(p) > 21 && p[9] == 1 && int(p[20]) == typ && int(p[21]) == code {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// A UDP source's datagrams go in one association, and what answers comes
// back to it; a tunnel that opens no UDP answers prohibited.
func TestUDP(t *testing.T) {
	r := newRig(t, []string{"tcp", "udp"}, map[string]int{})
	conn, err := gonet.DialUDP(r.machine, nil, ptr(addr("10.9.0.5:53")), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	for _, q := range []string{"query 1", "query 2"} {
		if _, err := conn.Write([]byte(q)); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 100)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for _, want := range []string{"re: query 1", "re: query 2"} {
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("answer %q: %q %v", want, buf[:n], err)
		}
	}
	r.core.mu.Lock()
	streams := map[uint64]bool{}
	for _, o := range r.core.opens {
		if o.UDP {
			streams[o.Stream] = true
		}
	}
	r.core.mu.Unlock()
	if len(streams) != 1 {
		t.Errorf("associations: %v", streams)
	}

	noUDP := newRig(t, []string{"tcp"}, map[string]int{})
	c2, _ := gonet.DialUDP(noUDP.machine, nil, ptr(addr("10.9.0.5:53")), ipv4.ProtocolNumber)
	defer func() { _ = c2.Close() }()
	drain(noUDP.dev.written)
	_, _ = c2.Write([]byte("query"))
	if !sawICMP(noUDP.dev.written, protocol.ICMPDestUnreachable, protocol.ICMPAdminProhibited) {
		t.Error("no prohibited for UDP the tunnel does not carry")
	}
}

func ptr[T any](v T) *T { return &v }

// A ping goes under the client's own sequence number and comes back with
// the machine's identifier and sequence; one the tunnel does not carry is
// answered prohibited.
func TestPing(t *testing.T) {
	r := newRig(t, []string{"tcp", "icmp"}, map[string]int{})
	me, host := netip.MustParseAddr("192.168.50.2"), netip.MustParseAddr("10.9.0.5")
	echo := protocol.ICMPMessage{Type: protocol.ICMPEchoRequest, ID: 4242, Seq: 17, Payload: []byte("abcdefgh")}.Bytes(false)
	pkt := ipv4Packet(me, host, 1, echo)
	drain(r.dev.written)
	r.dev.toClient <- pkt
	deadline := time.After(3 * time.Second)
	for {
		select {
		case p := <-r.dev.written:
			if len(p) < 28 || p[9] != 1 {
				continue
			}
			m, err := protocol.ReadICMP(p[20:], false)
			if err != nil || m.Type != protocol.ICMPEchoReply {
				continue
			}
			src, _ := netip.AddrFromSlice(p[12:16])
			if m.ID != 4242 || m.Seq != 17 || string(m.Payload) != "abcdefgh" || src != host {
				t.Fatalf("the reply: %+v from %s", m, src)
			}
			r.core.mu.Lock()
			if len(r.core.dgrams) != 1 || r.core.dgrams[0].Port != 0 || r.core.dgrams[0].Host != "10.9.0.5" {
				t.Errorf("the ping core got: %+v", r.core.dgrams)
			}
			r.core.mu.Unlock()
			return
		case <-deadline:
			t.Fatal("no echo reply")
		}
	}
}

// ipv4Packet is an IPv4 packet with a transport's bytes, its header's
// checksum filled in.
func ipv4Packet(src, dst netip.Addr, proto byte, payload []byte) []byte {
	h := make([]byte, 20, 20+len(payload))
	h[0], h[8], h[9] = 0x45, 64, proto
	n := 20 + len(payload)
	h[2], h[3] = byte(n>>8), byte(n)
	s, d := src.As4(), dst.As4()
	copy(h[12:], s[:])
	copy(h[16:], d[:])
	c := protocol.ICMPChecksum(h)
	h[10], h[11] = byte(c>>8), byte(c)
	return append(h, payload...)
}
