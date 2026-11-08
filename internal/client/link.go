package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/logoscore/logos-golang-protocol/protocol"
)

// The link's timing: a dial's, how long nothing heard means the link is
// dead (core pings every 30 s), a write's, and the reconnects' backoff.
const (
	dialWait   = 15 * time.Second
	readWait   = 90 * time.Second
	writeWait  = 10 * time.Second
	backoffMin = time.Second
	backoffMax = 30 * time.Second
)

// Refused is core not taking the client: its close's code
// (protocol.VPNCloseRefused, VPNCloseVersion) and why.
type Refused struct {
	Code int
	Why  string
}

func (r *Refused) Error() string {
	if r.Code == protocol.VPNCloseVersion {
		return "core speaks another link: " + r.Why
	}
	return "core refused the client: " + r.Why
}

// Ended is core ending the client: why.
type Ended struct{ Why string }

func (e *Ended) Error() string { return "core ended the client: " + e.Why }

// LinkURL is the link's WebSocket for a core's address (https, or http to a
// loopback address alone: a dev stack, an SSH forward).
func LinkURL(core string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(core), "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is no core address: https://logos.example.com", core)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("%s: plain http only to a loopback address; https otherwise", core)
		}
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("%q is no core address: https://logos.example.com", core)
	}
	u.Path, u.RawQuery, u.Fragment = protocol.VPNPath, "", ""
	return u.String(), nil
}

// Dial opens a link with the key, says the hello and reads core's welcome.
func Dial(ctx context.Context, linkURL, key string, hello protocol.VPNHello) (*websocket.Conn, protocol.VPNWelcome, error) {
	d := websocket.Dialer{HandshakeTimeout: dialWait, Proxy: http.ProxyFromEnvironment, ReadBufferSize: 64 << 10, WriteBufferSize: 64 << 10}
	conn, resp, err := d.DialContext(ctx, linkURL, http.Header{"Authorization": {"Bearer " + key}})
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
			return nil, protocol.VPNWelcome{}, fmt.Errorf("core answered %s: is this a Logos core's address?", resp.Status)
		}
		return nil, protocol.VPNWelcome{}, err
	}
	_ = resp.Body.Close()
	conn.SetReadLimit(protocol.MaxVPNFrame + 4<<10)
	b, _ := json.Marshal(protocol.VPNControl{Hello: &hello})
	_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
	if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
		_ = conn.Close()
		return nil, protocol.VPNWelcome{}, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(dialWait))
	kind, msg, err := conn.ReadMessage()
	if err != nil {
		_ = conn.Close()
		var ce *websocket.CloseError
		if errors.As(err, &ce) && (ce.Code == protocol.VPNCloseRefused || ce.Code == protocol.VPNCloseVersion) {
			return nil, protocol.VPNWelcome{}, &Refused{Code: ce.Code, Why: ce.Text}
		}
		return nil, protocol.VPNWelcome{}, err
	}
	var ctl protocol.VPNControl
	if kind != websocket.TextMessage || json.Unmarshal(msg, &ctl) != nil || ctl.Welcome == nil {
		_ = conn.Close()
		return nil, protocol.VPNWelcome{}, errors.New("core said no welcome")
	}
	return conn, *ctl.Welcome, nil
}

// Link carries the client over its links: one at a time, again within
// protocol.VPNLinkGrace of one dropping.
type Link struct {
	URL, Key string
	Hello    protocol.VPNHello
	Client   *Client
	// Routes is told the routes, as core changes them (and as a
	// reconnect's welcome says them).
	Routes func([]string)
	// Logf says what the link does, for a person.
	Logf func(format string, args ...any)
	// Grace is how long a link may stay down (protocol.VPNLinkGrace).
	Grace time.Duration

	mu   sync.Mutex
	conn *websocket.Conn
	wmu  sync.Mutex
}

// Run serves conn, and the links after it, until core ends the client,
// refuses it, a link stays down past the grace, or ctx ends (nil).
func (l *Link) Run(ctx context.Context, conn *websocket.Conn) error {
	grace := l.Grace
	if grace <= 0 {
		grace = protocol.VPNLinkGrace
	}
	for {
		err := l.serve(ctx, conn)
		var ended *Ended
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.As(err, &ended):
			return err
		}
		l.Logf("the link to core dropped (%v): connecting again", err)
		down := time.Now()
		backoff := backoffMin
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			c, w, err := Dial(ctx, l.URL, l.Key, l.Hello)
			if err == nil {
				if werr := l.Client.Welcome(w); werr != nil {
					_ = c.Close()
					return werr
				}
				if l.Routes != nil {
					l.Routes(w.Routes)
				}
				l.Logf("connected again")
				conn = c
				break
			}
			var refused *Refused
			if errors.As(err, &refused) || ctx.Err() != nil {
				return err
			}
			if time.Since(down) >= grace {
				return fmt.Errorf("the link to core stayed down past %s: %w", grace, err)
			}
			backoff = min(backoff*2, backoffMax)
		}
	}
}

// serve carries the client over one link until it fails.
func (l *Link) serve(ctx context.Context, conn *websocket.Conn) error {
	l.mu.Lock()
	l.conn = conn
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.conn = nil
		l.mu.Unlock()
		_ = conn.Close()
	}()
	conn.SetPingHandler(func(data string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readWait))
		return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(writeWait))
	})
	l.Client.Attach()
	stop := make(chan struct{})
	writeErr := make(chan error, 1)
	go func() { writeErr <- l.write(conn, stop) }()
	defer close(stop)
	readErr := make(chan error, 1)
	go func() { readErr <- l.read(conn) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-readErr:
		return err
	case err := <-writeErr:
		return err
	}
}

func (l *Link) read(conn *websocket.Conn) error {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(readWait))
		kind, b, err := conn.ReadMessage()
		if err != nil {
			var ce *websocket.CloseError
			if errors.As(err, &ce) && ce.Code == protocol.VPNCloseRefused {
				return &Ended{Why: ce.Text}
			}
			return err
		}
		switch kind {
		case websocket.BinaryMessage:
			if err := l.Client.Take(b); err != nil {
				l.Logf("a frame of core's does not read: %v", err)
			}
		case websocket.TextMessage:
			var ctl protocol.VPNControl
			if json.Unmarshal(b, &ctl) != nil {
				continue
			}
			if ctl.End != "" {
				return &Ended{Why: ctl.End}
			}
			if ctl.Routes != nil && l.Routes != nil {
				l.Routes(ctl.Routes)
			}
		}
	}
}

func (l *Link) write(conn *websocket.Conn, stop chan struct{}) error {
	for {
		for {
			frame, more := l.Client.NextFrame()
			if frame != nil {
				l.wmu.Lock()
				_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
				err := conn.WriteMessage(websocket.BinaryMessage, frame)
				l.wmu.Unlock()
				if err != nil {
					return err
				}
			}
			if !more {
				break
			}
		}
		select {
		case <-l.Client.Kick():
		case <-stop:
			return nil
		}
	}
}

// Bye tells core the client disconnects, and closes the link.
func (l *Link) Bye() {
	l.mu.Lock()
	conn := l.conn
	l.mu.Unlock()
	if conn == nil {
		return
	}
	b, _ := json.Marshal(protocol.VPNControl{Bye: true})
	l.wmu.Lock()
	_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
	_ = conn.WriteMessage(websocket.TextMessage, b)
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(writeWait))
	l.wmu.Unlock()
}
