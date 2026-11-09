package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/logoscore/logos-golang-protocol/protocol"
)

func TestLinkURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://logos.example.com":       "wss://logos.example.com/api/v1/vpn",
		"https://logos.example.com:8443/": "wss://logos.example.com:8443/api/v1/vpn",
		"http://localhost:8080":           "ws://localhost:8080/api/v1/vpn",
		"http://127.0.0.1:8080/app":       "ws://127.0.0.1:8080/api/v1/vpn",
	} {
		if got, err := LinkURL(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"http://logos.example.com", "logos.example.com", "ftp://x"} {
		if _, err := LinkURL(bad); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

var testHello = protocol.VPNHello{Link: protocol.VPNLink, Version: "test", OS: "linux", Arch: "amd64", Machine: "kali",
	Instance: "00112233445566778899aabbccddeeff"}

// fakeLinkCore is core's side of the link: it checks the key and the hello,
// and does what each connection's turn says.
type fakeLinkCore struct {
	mu     sync.Mutex
	hellos []protocol.VPNHello
	turns  []func(*websocket.Conn)
	task   string
}

func (f *fakeLinkCore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer lgv_0123456789ab_secret" {
		http.Error(w, "no key", http.StatusUnauthorized)
		return
	}
	up := websocket.Upgrader{}
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, b, err := conn.ReadMessage()
	var ctl protocol.VPNControl
	if err != nil || json.Unmarshal(b, &ctl) != nil || ctl.Hello == nil {
		return
	}
	f.mu.Lock()
	f.hellos = append(f.hellos, *ctl.Hello)
	turn := len(f.hellos) - 1
	var do func(*websocket.Conn)
	if turn < len(f.turns) {
		do = f.turns[turn]
	}
	f.mu.Unlock()
	if do != nil {
		do(conn)
	}
}

func (f *fakeLinkCore) welcome(routes ...string) func(*websocket.Conn) {
	return func(conn *websocket.Conn) {
		b, _ := json.Marshal(protocol.VPNControl{Welcome: &protocol.VPNWelcome{Task: f.task, Routes: routes, MaxStreams: 256,
			Opens: []string{"tcp"}, User: "alice"}})
		_ = conn.WriteMessage(websocket.TextMessage, b)
	}
}

func wsURL(srv *httptest.Server) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + protocol.VPNPath
}

// A refused key is core's close, said as it is.
func TestDialRefused(t *testing.T) {
	f := &fakeLinkCore{task: uuid.NewString()}
	f.turns = []func(*websocket.Conn){func(conn *websocket.Conn) {
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(protocol.VPNCloseRefused, "the key is unknown"), time.Now().Add(time.Second))
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	_, _, err := Dial(context.Background(), wsURL(srv), "lgv_0123456789ab_secret", testHello, nil)
	var refused *Refused
	if !errors.As(err, &refused) || refused.Code != protocol.VPNCloseRefused || refused.Why != "the key is unknown" {
		t.Fatalf("refused: %v", err)
	}
	if _, _, err := Dial(context.Background(), wsURL(srv), "lgv_wrong", testHello, nil); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a wrong key: %v", err)
	}
}

// A link that drops connects again with the same hello, its routes as the
// new welcome says them; core's end ends the run, saying why.
func TestLinkReconnectsAndEnds(t *testing.T) {
	f := &fakeLinkCore{task: uuid.NewString()}
	f.turns = []func(*websocket.Conn){
		f.welcome("10.0.0.0/24"),
		func(conn *websocket.Conn) {
			f.welcome("10.0.0.0/24", "10.0.1.0/24")(conn)
			b, _ := json.Marshal(protocol.VPNControl{End: "disconnected by bob"})
			_ = conn.WriteMessage(websocket.TextMessage, b)
			time.Sleep(100 * time.Millisecond)
		},
	}
	srv := httptest.NewServer(f)
	defer srv.Close()
	conn, w, err := Dial(context.Background(), wsURL(srv), "lgv_0123456789ab_secret", testHello, nil)
	if err != nil || w.User != "alice" {
		t.Fatalf("dial: %v", err)
	}
	c, err := New(w)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var routes [][]string
	l := &Link{URL: wsURL(srv), Key: "lgv_0123456789ab_secret", Hello: testHello, Client: c, Logf: t.Logf, Grace: 10 * time.Second,
		Routes: func(r []string) { mu.Lock(); routes = append(routes, r); mu.Unlock() }}
	err = l.Run(context.Background(), conn)
	var ended *Ended
	if !errors.As(err, &ended) || ended.Why != "disconnected by bob" {
		t.Fatalf("run: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hellos) != 2 || f.hellos[1].Instance != testHello.Instance {
		t.Errorf("hellos: %+v", f.hellos)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(routes) != 1 || len(routes[0]) != 2 {
		t.Errorf("routes said: %v", routes)
	}
}

// After a reconnect, an open not answered and bytes core did not ack go
// again.
func TestAttachResends(t *testing.T) {
	task := uuid.New()
	c, err := New(protocol.VPNWelcome{Task: task.String(), Routes: []string{"10.0.0.0/24"}, MaxStreams: 256, Opens: []string{"tcp", "udp"}})
	if err != nil {
		t.Fatal(err)
	}
	c.UDP(mustAddrPort("192.168.1.10:5000"), mustAddrPort("10.0.0.5:53"), []byte("q"))
	first, _ := c.NextFrame()
	if again, _ := c.NextFrame(); again != nil {
		t.Fatal("an open sent twice on one link")
	}
	c.Attach()
	second, _ := c.NextFrame()
	if first == nil || second == nil {
		t.Fatalf("the open, then again after a reconnect: %v %v", first != nil, second != nil)
	}
	items, _ := protocol.ReadVPNFrame(second)
	if len(items) != 1 || protocol.ItemType(items[0]) != protocol.ItemTunnel {
		t.Errorf("after a reconnect: %d items", len(items))
	}
}

func mustAddrPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
