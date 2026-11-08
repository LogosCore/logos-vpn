// Package system sets up logos-vpn's interface on the machine (docs:
// contracts/vpn-front, On the machine): an address of its own, and a route
// through it for each of the tunnel's networks the machine does not reach
// already. The interface going takes its routes with it.
package system

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// The interface's own addresses: from ranges no target network uses as
// its own (RFC 2544's benchmarking range; a unique local IPv6 prefix).
var (
	OwnIPv4 = netip.MustParseAddr("198.18.255.1")
	OwnIPv6 = netip.MustParseAddr("fdc0:6c6f:676f:7300::1")
)

// LeftOut is a route the client does not add, and why.
type LeftOut struct {
	Route netip.Prefix
	Why   string
}

// Network is one of the machine's own networks: an interface's.
type Network struct {
	Prefix    netip.Prefix
	Interface string
}

// OwnNetworks are the machine's networks, by its interfaces' addresses, but
// the client's own interface's (and loopback's).
func OwnNetworks(client string) []Network {
	var out []Network
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Name == client || ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			p, err := netip.ParsePrefix(ipn.String())
			if err != nil || p.Addr().IsLinkLocalUnicast() {
				continue
			}
			out = append(out, Network{Prefix: p.Masked(), Interface: ifc.Name})
		}
	}
	return out
}

// Plan is what of the tunnel's routes the client adds: none that overlaps
// a network the machine reaches another way (its own stay its own), nor
// one that holds core's address (the client's own link would go into the
// tunnel).
func Plan(routes []netip.Prefix, own []Network, core []netip.Addr) (add []netip.Prefix, left []LeftOut) {
	for _, r := range routes {
		why := ""
		for _, a := range core {
			if r.Contains(a.Unmap()) {
				why = fmt.Sprintf("it holds core's address, %s: the client's own link would go into the tunnel", a.Unmap())
				break
			}
		}
		if why == "" {
			for _, n := range own {
				if n.Prefix.Overlaps(r) {
					why = fmt.Sprintf("this machine reaches it through %s (%s)", n.Interface, n.Prefix)
					break
				}
			}
		}
		if why != "" {
			left = append(left, LeftOut{Route: r, Why: why})
			continue
		}
		add = append(add, r)
	}
	return add, left
}

// Diff is what changes from routes now to routes then: those to add, and
// those to take away.
func Diff(now, then []netip.Prefix) (add, del []netip.Prefix) {
	for _, r := range then {
		if !slices.Contains(now, r) {
			add = append(add, r)
		}
	}
	for _, r := range now {
		if !slices.Contains(then, r) {
			del = append(del, r)
		}
	}
	return add, del
}

// run runs a command of the system's, its output in the error.
func run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
