// logos-vpn routes this machine into a Logos tunnel's networks (docs:
// contracts/vpn-front): while it runs, every tool here reaches the
// tunnel's routes through its minion. Ctrl-C disconnects it.
//
//	sudo logos-vpn https://logos.example.com lgv_…
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-vpn/internal/client"
	"github.com/logoscore/logos-vpn/internal/netstack"
	"github.com/logoscore/logos-vpn/internal/system"
	"golang.zx2c4.com/wireguard/tun"
)

// version is the release, set at build (-ldflags "-X main.version=…").
var version = "dev"

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "logos-vpn: "+format+"\n", args...)
}

func main() {
	if err := run(); err != nil {
		logf("%v", err)
		os.Exit(1)
	}
}

func defaultName() string {
	switch runtime.GOOS {
	case "darwin":
		return "utun"
	case "windows":
		return "logos-vpn"
	}
	return "logos0"
}

func run() error {
	name := flag.String("interface", defaultName(), "the interface's name (macOS: utun, any free one)")
	mtu := flag.Int("mtu", 1500, "the interface's MTU")
	showVersion := flag.Bool("version", false, "print the release and exit")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "usage: logos-vpn [-interface name] [-mtu n] <core address> <key>\n\n"+
			"Routes this machine into a Logos tunnel's networks while it runs; Ctrl-C disconnects it.\n"+
			"The key (lgv_…) comes from the tunnel's VPN tab (Connect a machine), or LOGOS_VPN_KEY.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	args := flag.Args()
	key := os.Getenv("LOGOS_VPN_KEY")
	if len(args) == 2 {
		key = args[1]
	}
	if len(args) < 1 || len(args) > 2 || key == "" {
		flag.Usage()
		os.Exit(2)
	}
	if !strings.HasPrefix(key, protocol.VPNKeyPrefix) {
		return fmt.Errorf("%q is no VPN key: lgv_…, from the tunnel's VPN tab (Connect a machine)", key)
	}
	linkURL, err := client.LinkURL(args[0])
	if err != nil {
		return err
	}
	if err := privileged(); err != nil {
		return err
	}
	machine, _ := os.Hostname()
	if machine == "" {
		machine = "machine"
	}
	instance := make([]byte, 16)
	if _, err := rand.Read(instance); err != nil {
		return err
	}
	hello := protocol.VPNHello{Link: protocol.VPNLink, Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH, Machine: machine,
		Instance: hex.EncodeToString(instance)}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	conn, welcome, err := client.Dial(ctx, linkURL, key, hello)
	if err != nil {
		return err
	}
	u, _ := url.Parse(args[0])
	logf("connected to %s as %s: task %s… (session %d)", u.Host, welcome.User, shortID(welcome.Task), welcome.Session)
	c, err := client.New(welcome)
	if err != nil {
		_ = conn.Close()
		return err
	}

	if err := ensureWintun(); err != nil {
		_ = conn.Close()
		return fmt.Errorf("wintun.dll beside logos-vpn: %w", err)
	}
	dev, err := tun.CreateTUN(*name, *mtu)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("the interface: %w", err)
	}
	ifname, _ := dev.Name()
	defer func() { _ = dev.Close() }()
	ifc, err := system.Configure(ifname)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("the interface %s: %w", ifname, err)
	}
	defer func() { _ = ifc.Close() }()
	coreAddrs := resolve(u.Hostname())
	routes := newRoutes(ifc, ifname, coreAddrs)
	routes.set(welcome.Routes)

	st, err := netstack.New(dev, *mtu, c)
	if err != nil {
		_ = conn.Close()
		return err
	}
	c.SetWriter(st)
	st.Run()
	defer st.Close()

	go func() {
		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				c.Sweep()
			}
		}
	}()

	link := &client.Link{URL: linkURL, Key: key, Hello: hello, Client: c, Logf: logf, Routes: func(r []string) {
		if prefixes, err := protocol.TunnelRoutes(r); err == nil {
			c.SetRoutes(prefixes)
		}
		routes.set(r)
	}}
	done := make(chan error, 1)
	go func() { done <- link.Run(ctx, conn) }()
	select {
	case err = <-done:
	case err = <-st.Err():
		err = fmt.Errorf("the interface failed: %w", err)
	case <-ctx.Done():
		link.Bye()
		err = nil
	}
	c.End()
	logf("disconnected: %s's routes go", ifname)
	var ended *client.Ended
	if errors.As(err, &ended) {
		logf("%s", ended.Why)
		return nil
	}
	return err
}

// routesNow keeps the routes added through the interface, in step with
// the tunnel's.
type routesNow struct {
	mu     sync.Mutex
	ifc    *system.Interface
	ifname string
	core   []netip.Addr
	added  []netip.Prefix
}

func newRoutes(ifc *system.Interface, ifname string, core []netip.Addr) *routesNow {
	return &routesNow{ifc: ifc, ifname: ifname, core: core}
}

// set adds the tunnel's routes the machine does not reach already, and
// takes away those it no longer has, saying what it did.
func (r *routesNow) set(routes []string) {
	prefixes, err := protocol.TunnelRoutes(routes)
	if err != nil {
		logf("core's routes do not read: %v", err)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	want, left := system.Plan(prefixes, system.OwnNetworks(r.ifname), r.core)
	add, del := system.Diff(r.added, want)
	for _, p := range del {
		if err := r.ifc.DelRoute(p); err != nil {
			logf("%s: %v", p, err)
		}
	}
	var added []string
	for _, p := range add {
		if err := r.ifc.AddRoute(p); err != nil {
			logf("%s left out: %v", p, err)
			want = remove(want, p)
			continue
		}
		added = append(added, p.String())
	}
	r.added = want
	if len(added) > 0 {
		logf("%s: %s", r.ifname, strings.Join(added, ", "))
	}
	for _, l := range left {
		logf("%s left out: %s", l.Route, l.Why)
	}
	if len(del) > 0 {
		var gone []string
		for _, p := range del {
			gone = append(gone, p.String())
		}
		logf("routes no longer the tunnel's: %s", strings.Join(gone, ", "))
	}
}

func remove(ps []netip.Prefix, p netip.Prefix) []netip.Prefix {
	out := ps[:0]
	for _, q := range ps {
		if q != p {
			out = append(out, q)
		}
	}
	return out
}

// resolve is core's addresses, as this machine reaches it.
func resolve(host string) []netip.Addr {
	var out []netip.Addr
	ips, _ := net.LookupIP(host)
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
