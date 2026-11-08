// Package client is logos-vpn's side of the VPN link (docs:
// contracts/vpn-front, The link): the streams the client opens for the
// machine's flows (a TCP connection, a UDP source's association, its
// pings), carried as tunnel items with offsets, acks and windows, as a
// minion's streams are, so a link that drops and comes back loses nothing:
// each side sends again from the other's last ack.
package client

import (
	"bytes"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-vpn/internal/netstack"
)

// Writer writes what comes back to the machine (the stack).
type Writer interface {
	WriteUDP(from, to netip.AddrPort, payload []byte)
	WriteEchoReply(from, to netip.Addr, id, seq uint16, payload []byte)
	WriteICMPError(from netip.Addr, orig []byte, typ, code int)
}

const (
	// window is the room the client gives each stream: what it holds of
	// core's bytes for the machine. The default room, so its opens leave
	// it out.
	window = protocol.DefaultTunnelRoom
	// held is the most the client holds of the machine's bytes for core.
	held = 1 << 20
	// readPiece is how much one read of the machine's connection takes.
	readPiece = 32 << 10
	// openWait is how long a connection waits for the minion's answer:
	// past core's own wait (the command's timeout and 30 s).
	openWait = 2 * time.Minute
	// datagramQueue bounds the datagrams held for a stream not open yet,
	// and for the link.
	datagramQueue = 256 << 10
	// pingWait is how long a ping's answer is waited for.
	pingWait = time.Minute
	// itemOverhead and dataHeader are what an item and a tunnel_data take
	// besides their bytes; minPiece the least a tunnel_data carries when
	// a stream has more; frameData what a frame's data takes at most.
	itemOverhead = 8
	dataHeader   = 64
	minPiece     = 1 << 10
	frameData    = protocol.MaxVPNFrame - 32<<10
)

type kind int

const (
	kindTCP kind = iota
	kindUDP
	kindICMP
)

// Client is the client's streams over its link.
type Client struct {
	mu         sync.Mutex
	task       []byte
	routes     []netip.Prefix
	udp, icmp  bool
	maxStreams int
	w          Writer
	now        func() time.Time

	last     uint64
	streams  map[uint64]*stream
	bySource map[netip.AddrPort]*stream
	pinger   *stream
	pings    map[uint16]ping
	pingSeq  uint16
	// What goes with the link's next frame: closes, datagrams.
	closes     []protocol.TunnelCloseItem
	dgrams     []protocol.TunnelDatagramItem
	dgramBytes int
	rotation   int
	kick       chan struct{}
	ended      chan struct{}
	endOnce    sync.Once
}

// ping is an echo request of the machine's, sent under the client's own
// sequence number: what answers goes back with the machine's.
type ping struct {
	src, dst netip.Addr
	id, seq  uint16
	orig     []byte
	at       time.Time
}

// New is a client of a tunnel, as core's welcome says it.
func New(w protocol.VPNWelcome) (*Client, error) {
	c := &Client{streams: map[uint64]*stream{}, bySource: map[netip.AddrPort]*stream{}, pings: map[uint16]ping{},
		kick: make(chan struct{}, 1), ended: make(chan struct{}), now: time.Now}
	if err := c.Welcome(w); err != nil {
		return nil, err
	}
	return c, nil
}

// Welcome takes core's welcome (again, on each reconnect): the task, the
// routes and what the command opens.
func (c *Client) Welcome(w protocol.VPNWelcome) error {
	task, err := uuidBytes(w.Task)
	if err != nil {
		return err
	}
	routes, err := protocol.TunnelRoutes(w.Routes)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.task, c.routes, c.maxStreams = task, routes, w.MaxStreams
	c.udp, c.icmp = slices.Contains(w.Opens, protocol.OpenUDP), slices.Contains(w.Opens, protocol.OpenICMP)
	return nil
}

// SetWriter gives the client the stack's writer.
func (c *Client) SetWriter(w Writer) {
	c.mu.Lock()
	c.w = w
	c.mu.Unlock()
}

// SetRoutes takes the tunnel's routes, changed.
func (c *Client) SetRoutes(routes []netip.Prefix) {
	c.mu.Lock()
	c.routes = routes
	c.mu.Unlock()
}

// Kick says when the link has something to send.
func (c *Client) Kick() <-chan struct{} { return c.kick }

func (c *Client) kickLink() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// Routed says whether addr is in the tunnel's routes.
func (c *Client) Routed(addr netip.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return protocol.TunnelRouted(c.routes, addr)
}

// stream is one of the client's streams.
type stream struct {
	c    *Client
	id   uint64
	kind kind
	src  netip.AddrPort
	open protocol.TunnelItem
	// openSent: its open went over the link now up; reply is core's.
	openSent bool
	reply    *protocol.TunnelReplyItem
	replied  chan int
	gone     bool
	done     chan struct{}
	conn     *netstack.Conn
	// peerClosed: core said done; the stream goes once the machine has
	// every byte.
	peerClosed bool

	// To core: the machine's bytes from outBase (core's next) not acked,
	// sent up to outSent, nothing past outLimit; outEOF: the machine sends
	// no more; outDone: core has it all.
	outBuf    []byte
	outBase   uint64
	outSent   uint64
	outLimit  uint64
	outEOF    bool
	outDone   bool
	outSignal chan struct{}

	// From core: taken up to inNext (its eof counted); inBuf not yet
	// written to the machine; inEOF its eof; inShut the machine has it.
	inNext   uint64
	inBuf    []byte
	inEOF    bool
	inShut   bool
	ackDue   bool
	ackedEnd uint64
	inSignal chan struct{}

	// A datagram stream's: what waits for its open, its datagrams'
	// numbers, those core sent, taken once each, and when one last went.
	pending      []protocol.TunnelDatagramItem
	pendingBytes int
	seqOut       uint64
	seen         replayWindow
	lastActive   time.Time
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// newStream numbers a stream and queues its open (c.mu held).
func (c *Client) newStream(k kind, src netip.AddrPort, open protocol.TunnelItem) *stream {
	c.last++
	open.T, open.Task, open.Stream = protocol.ItemTunnel, c.task, c.last
	s := &stream{c: c, id: c.last, kind: k, src: src, open: open, replied: make(chan int, 1), done: make(chan struct{}),
		outSignal: make(chan struct{}, 1), inSignal: make(chan struct{}, 1), lastActive: c.now(), outLimit: window}
	c.streams[s.id] = s
	c.kickLink()
	return s
}

// remove forgets a stream (c.mu held).
func (c *Client) remove(s *stream) {
	if s.gone {
		return
	}
	s.gone = true
	close(s.done)
	delete(c.streams, s.id)
	if c.bySource[s.src] == s {
		delete(c.bySource, s.src)
	}
	if c.pinger == s {
		c.pinger = nil
	}
}

// closeStream tells core a stream of the client's is over.
func (c *Client) closeStream(s *stream, reason int) {
	c.closes = append(c.closes, protocol.TunnelCloseItem{T: protocol.ItemTunnelClose, Task: c.task, Stream: s.id, Reason: reason})
	c.kickLink()
}

// TCP opens a stream for a connection of the machine's (netstack.Handler):
// it waits for the minion's answer.
func (c *Client) TCP(src, dst netip.AddrPort) (netstack.TCPStream, int) {
	c.mu.Lock()
	if !protocol.TunnelRouted(c.routes, dst.Addr()) {
		c.mu.Unlock()
		return nil, protocol.TunnelDenied
	}
	s := c.newStream(kindTCP, src, protocol.TunnelItem{Host: dst.Addr().Unmap().String(), Port: uint64(dst.Port())})
	c.mu.Unlock()
	timer := time.NewTimer(openWait)
	defer timer.Stop()
	select {
	case result := <-s.replied:
		if result != protocol.TunnelOpen {
			return nil, result
		}
		return tcpStream{s}, result
	case <-timer.C:
		c.mu.Lock()
		if !s.gone {
			c.closeStream(s, protocol.TunnelCloseReset)
			c.remove(s)
		}
		c.mu.Unlock()
		return nil, protocol.TunnelTimedOut
	case <-c.ended:
		return nil, protocol.TunnelFailed
	}
}

// UDP sends a datagram of the machine's in its source's association
// (netstack.Handler): false when the tunnel carries no UDP.
func (c *Client) UDP(src, dst netip.AddrPort, payload []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.udp {
		return false
	}
	s := c.bySource[src]
	if s == nil {
		s = c.newStream(kindUDP, src, protocol.TunnelItem{UDP: true})
		c.bySource[src] = s
	}
	c.datagram(s, protocol.TunnelDatagramItem{Host: dst.Addr().Unmap().String(), Port: uint64(dst.Port()), Data: payload})
	return true
}

// Ping sends an echo request of the machine's in the client's pings
// (netstack.Handler), under its own sequence number: false when the tunnel
// carries no pings.
func (c *Client) Ping(src, dst netip.Addr, echo protocol.ICMPMessage, orig []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.icmp {
		return false
	}
	if c.pinger == nil {
		c.pinger = c.newStream(kindICMP, netip.AddrPort{}, protocol.TunnelItem{Kind: protocol.TunnelKindICMP})
	}
	c.pingSeq++
	seq := c.pingSeq
	c.pings[seq] = ping{src: src, dst: dst, id: echo.ID, seq: echo.Seq, orig: orig, at: c.now()}
	v6 := !dst.Unmap().Is4()
	msg := protocol.ICMPMessage{Type: echo.Type, Seq: seq, Payload: echo.Payload}.Bytes(v6)
	c.datagram(c.pinger, protocol.TunnelDatagramItem{Host: dst.Unmap().String(), Data: msg})
	return true
}

// datagram queues a datagram of a stream's: for the link once it opened,
// held until then (c.mu held); past the queue, dropped as UDP drops.
func (c *Client) datagram(s *stream, d protocol.TunnelDatagramItem) {
	d.T, d.Task, d.Stream = protocol.ItemTunnelDatagram, c.task, s.id
	s.lastActive = c.now()
	if s.reply == nil {
		if s.pendingBytes+len(d.Data) <= datagramQueue {
			s.pending = append(s.pending, d)
			s.pendingBytes += len(d.Data)
		}
		return
	}
	c.queueDatagram(s, d)
}

func (c *Client) queueDatagram(s *stream, d protocol.TunnelDatagramItem) {
	if c.dgramBytes+len(d.Data) > datagramQueue {
		return
	}
	d.Seq = s.seqOut
	s.seqOut++
	c.dgrams = append(c.dgrams, d)
	c.dgramBytes += len(d.Data)
	c.kickLink()
}

// tcpStream runs an open TCP stream over the machine's connection.
type tcpStream struct{ s *stream }

func (t tcpStream) Run(conn *netstack.Conn) { t.s.c.run(t.s, conn) }

// run carries a TCP stream's bytes both ways once the stack completed the
// machine's handshake.
func (c *Client) run(s *stream, conn *netstack.Conn) {
	c.mu.Lock()
	if s.gone {
		c.mu.Unlock()
		conn.Abort()
		return
	}
	s.conn = conn
	c.mu.Unlock()
	go c.readLocal(s, conn)
	c.writeLocal(s, conn)
}

// outFree is how much more of the machine's bytes the client may hold.
func (s *stream) outFree() int {
	if s.outEOF {
		return 0
	}
	limit := min(s.outLimit-min(s.outLimit, s.outBase), held)
	return max(int(limit)-len(s.outBuf), 0)
}

// readLocal reads the machine's bytes for core, within core's room.
func (c *Client) readLocal(s *stream, conn *netstack.Conn) {
	buf := make([]byte, readPiece)
	for {
		c.mu.Lock()
		for !s.gone && s.outFree() == 0 && !s.outEOF {
			c.mu.Unlock()
			select {
			case <-s.outSignal:
			case <-s.done:
			}
			c.mu.Lock()
		}
		if s.gone || s.outEOF {
			c.mu.Unlock()
			return
		}
		n := min(len(buf), s.outFree())
		c.mu.Unlock()
		k, err := conn.Read(buf[:n])
		c.mu.Lock()
		if s.gone {
			c.mu.Unlock()
			return
		}
		if k > 0 {
			s.outBuf = append(s.outBuf, buf[:k]...)
			c.kickLink()
		}
		if err != nil {
			if isEOF(err) {
				s.outEOF = true
				c.kickLink()
			} else {
				// The machine's end reset: so is the stream.
				c.closeStream(s, protocol.TunnelCloseReset)
				c.remove(s)
			}
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
	}
}

// writeLocal writes core's bytes to the machine, giving the room back,
// then core's eof; the stream ends once both ends finished.
func (c *Client) writeLocal(s *stream, conn *netstack.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		c.mu.Lock()
		// Waits while nothing is to write, no eof to pass on, and the
		// stream is not over.
		for !s.gone && len(s.inBuf) == 0 && (!s.inEOF || s.inShut) && (!s.inShut || !s.outDone) {
			c.mu.Unlock()
			select {
			case <-s.inSignal:
			case <-s.done:
			}
			c.mu.Lock()
		}
		if s.gone {
			reset := !s.inShut || !s.outDone
			c.mu.Unlock()
			if reset {
				conn.Abort()
			}
			return
		}
		if len(s.inBuf) == 0 {
			if s.inEOF && !s.inShut {
				s.inShut = true
				c.mu.Unlock()
				_ = conn.CloseWrite()
				c.mu.Lock()
			}
			done := c.over(s)
			c.mu.Unlock()
			if done {
				return
			}
			continue
		}
		piece := s.inBuf[:min(len(s.inBuf), readPiece)]
		c.mu.Unlock()
		_, err := conn.Write(piece)
		c.mu.Lock()
		if s.gone {
			c.mu.Unlock()
			conn.Abort()
			return
		}
		if err != nil {
			c.closeStream(s, protocol.TunnelCloseReset)
			c.remove(s)
			c.mu.Unlock()
			return
		}
		s.inBuf = s.inBuf[len(piece):]
		if len(s.inBuf) == 0 {
			s.inBuf = nil
		}
		if s.roomGrew() {
			c.kickLink()
		}
		c.mu.Unlock()
	}
}

// over ends a TCP stream both ends finished (c.mu held): core has the
// machine's every byte and eof, the machine core's. The client says done,
// unless core said it first.
func (c *Client) over(s *stream) bool {
	if s.gone || !s.outDone || !s.inShut {
		return false
	}
	if !s.peerClosed {
		c.closeStream(s, protocol.TunnelCloseDone)
	}
	c.remove(s)
	return true
}

// roomGrew marks an ack due once core may send a quarter of the window
// more than the acks sent let it.
func (s *stream) roomGrew() bool {
	if s.ackDue || s.inEOF {
		return false
	}
	room := uint64(max(window-len(s.inBuf), 0))
	if s.inNext+room >= s.ackedEnd+uint64(window/4) {
		s.ackDue = true
		return true
	}
	return false
}

// Attach is a new link up, past core's welcome: what the link before may
// have lost goes again (opens not answered, bytes from core's last ack,
// acks).
func (c *Client) Attach() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.streams {
		if s.reply == nil {
			s.openSent = false
		}
		s.outSent = s.outBase
		if s.reply != nil && s.kind == kindTCP {
			s.ackDue = true
		}
	}
	c.kickLink()
}

// End ends the client: every stream resets, nothing more opens.
func (c *Client) End() {
	c.endOnce.Do(func() { close(c.ended) })
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.streams {
		c.remove(s)
	}
}

// Sweep ends the datagram streams idle past protocol.TunnelUDPIdle, and
// forgets pings that went unanswered.
func (c *Client) Sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for _, s := range c.streams {
		if s.kind != kindTCP && now.Sub(s.lastActive) >= protocol.TunnelUDPIdle {
			c.closeStream(s, protocol.TunnelCloseDone)
			c.remove(s)
		}
	}
	for seq, p := range c.pings {
		if now.Sub(p.at) >= pingWait {
			delete(c.pings, seq)
		}
	}
}

// Streams is how many streams the client has now.
func (c *Client) Streams() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.streams)
}

// Take takes a frame of core's: its replies, bytes, acks, closes and
// datagrams. An item that does not read is dropped.
func (c *Client) Take(frame []byte) error {
	items, err := protocol.ReadVPNFrame(frame)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, raw := range items {
		c.take(raw)
	}
	return nil
}

func read(raw cbor.RawMessage, v interface{ Validate() error }) bool {
	return protocol.UnmarshalCBOR(raw, v) == nil && v.Validate() == nil
}

// take is one item of core's (c.mu held).
func (c *Client) take(raw cbor.RawMessage) {
	switch protocol.ItemType(raw) {
	case protocol.ItemTunnelReply:
		var r protocol.TunnelReplyItem
		if read(raw, &r) && bytes.Equal(r.Task, c.task) {
			c.takeReply(r)
		}
	case protocol.ItemTunnelData:
		var d protocol.TunnelDataItem
		if read(raw, &d) && bytes.Equal(d.Task, c.task) {
			c.takeData(d)
		}
	case protocol.ItemTunnelAck:
		var a protocol.TunnelAckItem
		if read(raw, &a) && bytes.Equal(a.Task, c.task) {
			c.takeAck(a)
		}
	case protocol.ItemTunnelClose:
		var cl protocol.TunnelCloseItem
		if read(raw, &cl) && bytes.Equal(cl.Task, c.task) {
			c.takeClose(cl)
		}
	case protocol.ItemTunnelDatagram:
		var d protocol.TunnelDatagramItem
		if read(raw, &d) && bytes.Equal(d.Task, c.task) {
			c.takeDatagram(d)
		}
	}
}

func (c *Client) takeReply(r protocol.TunnelReplyItem) {
	s := c.streams[r.Stream]
	if s == nil || s.reply != nil {
		return
	}
	s.reply = &r
	if r.Result != protocol.TunnelOpen {
		c.remove(s)
		s.replied <- r.Result
		return
	}
	s.outLimit = protocol.TunnelRoom(r.Room)
	s.ackedEnd = window
	for _, d := range s.pending {
		c.queueDatagram(s, d)
	}
	s.pending, s.pendingBytes = nil, 0
	s.replied <- r.Result
}

func (c *Client) takeData(d protocol.TunnelDataItem) {
	s := c.streams[d.Stream]
	if s == nil || s.kind != kindTCP || s.reply == nil {
		return
	}
	s.ackDue = true
	c.kickLink()
	if s.inEOF || d.End() <= s.inNext || d.Off > s.inNext {
		return
	}
	data := d.Data[s.inNext-d.Off:]
	eof := d.EOF
	if free := max(window-len(s.inBuf), 0); len(data) > free {
		data, eof = data[:free], false
	}
	s.inBuf = append(s.inBuf, data...)
	s.inNext += uint64(len(data))
	if eof {
		s.inEOF = true
		s.inNext++
	}
	signal(s.inSignal)
}

func (c *Client) takeAck(a protocol.TunnelAckItem) {
	s := c.streams[a.Stream]
	if s == nil || s.kind != kindTCP || s.reply == nil {
		return
	}
	end := s.outBase + uint64(len(s.outBuf))
	if s.outDone || a.Next < s.outBase || a.Next > end+1 || (a.Next == end+1 && !s.outEOF) {
		return
	}
	room := s.outLimit - min(s.outLimit, s.outBase)
	if a.Room != nil {
		room = *a.Room
	}
	if a.Next == end+1 {
		s.outBuf, s.outBase, s.outDone = nil, end, true
	} else {
		s.outBuf = s.outBuf[a.Next-s.outBase:]
		s.outBase = a.Next
	}
	s.outSent = max(s.outSent, a.Next)
	s.outLimit = max(s.outLimit, a.Next+room)
	signal(s.outSignal)
	signal(s.inSignal)
	c.kickLink()
}

func (c *Client) takeClose(cl protocol.TunnelCloseItem) {
	s := c.streams[cl.Stream]
	if s == nil {
		return
	}
	if cl.Reason == protocol.TunnelCloseDone && s.kind == kindTCP && s.reply != nil {
		// Both ends finished: the machine gets the rest, then it goes.
		s.peerClosed, s.outDone = true, true
		if !c.over(s) {
			signal(s.inSignal)
		}
		return
	}
	if s.reply == nil {
		// Not opened: an answer of its own, should its reply never come.
		select {
		case s.replied <- protocol.TunnelFailed:
		default:
		}
	}
	c.remove(s)
}

func (c *Client) takeDatagram(d protocol.TunnelDatagramItem) {
	s := c.streams[d.Stream]
	if s == nil || s.reply == nil || !s.seen.take(d.Seq) || c.w == nil {
		return
	}
	from, err := netip.ParseAddr(d.Host)
	if err != nil {
		return
	}
	s.lastActive = c.now()
	switch s.kind {
	case kindUDP:
		c.w.WriteUDP(netip.AddrPortFrom(from, uint16(d.Port)), s.src, d.Data)
	case kindICMP:
		m, err := protocol.ReadICMP(d.Data, from.Is6() && !from.Is4In6())
		if err != nil {
			return
		}
		seq := m.Seq
		if m.Quoted != nil {
			seq = m.Quoted.Seq
		}
		p, ok := c.pings[seq]
		if !ok {
			return
		}
		delete(c.pings, seq)
		if m.Quoted != nil {
			c.w.WriteICMPError(from, p.orig, m.Type, m.Code)
			return
		}
		c.w.WriteEchoReply(from, p.src, p.id, p.seq, m.Payload)
	}
}

// NextFrame is what goes to core next: opens, closes, acks, datagrams,
// then each stream's bytes in turn while the frame has room; nil for
// nothing. more: another frame waits.
func (c *Client) NextFrame() (frame []byte, more bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f := &fill{room: frameData}
	streams := make([]*stream, 0, len(c.streams))
	for _, s := range c.streams {
		streams = append(streams, s)
	}
	slices.SortFunc(streams, func(a, b *stream) int { return compare(a.id, b.id) })
	for _, s := range streams {
		if s.reply == nil && !s.openSent && f.put(s.open) {
			s.openSent = true
		}
	}
	for len(c.closes) > 0 && f.put(c.closes[0]) {
		c.closes = c.closes[1:]
	}
	for _, s := range streams {
		if !s.ackDue || s.kind != kindTCP || s.reply == nil {
			continue
		}
		room := uint64(max(window-len(s.inBuf), 0))
		if s.inEOF {
			room = 0
		}
		if !f.put(protocol.TunnelAckItem{T: protocol.ItemTunnelAck, Task: c.task, Stream: s.id, Next: s.inNext, Room: &room}) {
			break
		}
		s.ackDue, s.ackedEnd = false, s.inNext+room
	}
	for len(c.dgrams) > 0 && f.put(c.dgrams[0]) {
		c.dgramBytes -= len(c.dgrams[0].Data)
		c.dgrams = c.dgrams[1:]
	}
	if n := len(streams); n > 0 {
		start := c.rotation % n
		c.rotation++
		for moved := true; moved; {
			moved = false
			for i := range n {
				s := streams[(start+i)%n]
				d := s.dataItem(c.task, min(f.dataRoom(), protocol.MaxTunnelData))
				if d == nil {
					continue
				}
				if !f.put(*d) {
					break
				}
				s.outSent = d.End()
				moved = true
			}
		}
	}
	more = f.full || len(c.closes)+len(c.dgrams) > 0
	for _, s := range streams {
		more = more || (s.reply == nil && !s.openSent) || (s.ackDue && s.reply != nil && s.kind == kindTCP) ||
			s.dataItem(c.task, protocol.MaxTunnelData) != nil
	}
	if len(f.items) == 0 {
		return nil, false
	}
	frame, err := protocol.VPNFrame(f.items)
	if err != nil {
		return nil, false
	}
	return frame, more
}

// dataItem is a TCP stream's next tunnel_data in room bytes: what was not
// sent, up to core's room, then the machine's eof; nil for none.
func (s *stream) dataItem(task []byte, room int) *protocol.TunnelDataItem {
	if s.kind != kindTCP || s.reply == nil || s.gone || s.outDone || room <= 0 {
		return nil
	}
	end := s.outBase + uint64(len(s.outBuf))
	sent := s.outSent
	n := 0
	if limit := min(end, s.outLimit); sent < limit {
		n = int(limit - sent)
	}
	eof := s.outEOF && sent <= end && sent+uint64(n) == end
	if n == 0 && !eof {
		return nil
	}
	if n > room {
		if room < minPiece {
			return nil
		}
		n, eof = room, false
	}
	d := protocol.TunnelDataItem{T: protocol.ItemTunnelData, Task: task, Stream: s.id, Off: sent, EOF: eof}
	if n > 0 {
		from := int(sent - s.outBase)
		d.Data = s.outBuf[from : from+n]
	}
	return &d
}

// fill is one frame's room for items.
type fill struct {
	items []cbor.RawMessage
	room  int
	full  bool
}

func (f *fill) put(v any) bool {
	if len(f.items) >= protocol.MaxVPNFrameItems {
		f.full = true
		return false
	}
	item, err := protocol.MarshalCBOR(v)
	if err != nil {
		return false
	}
	if len(item)+itemOverhead > f.room {
		f.full = true
		return false
	}
	f.room -= len(item) + itemOverhead
	f.items = append(f.items, item)
	return true
}

func (f *fill) dataRoom() int {
	if len(f.items) >= protocol.MaxVPNFrameItems {
		return 0
	}
	return max(f.room-itemOverhead-dataHeader, 0)
}

func compare(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
