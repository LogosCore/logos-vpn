package system

import "net/netip"

// Interface is the client's interface on macOS: a utun.
type Interface struct{ name string }

// Configure brings the utun up with its own addresses (a point-to-point
// pair, as a utun takes).
func Configure(name string) (*Interface, error) {
	if err := run("ifconfig", name, "inet", OwnIPv4.String(), OwnIPv4.String(), "netmask", "255.255.255.255", "up"); err != nil {
		return nil, err
	}
	_ = run("ifconfig", name, "inet6", OwnIPv6.String(), "prefixlen", "128")
	return &Interface{name: name}, nil
}

func family(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "-inet"
	}
	return "-inet6"
}

// AddRoute routes a network through the utun.
func (i *Interface) AddRoute(p netip.Prefix) error {
	return run("route", "-q", "-n", "add", family(p), p.String(), "-interface", i.name)
}

// DelRoute takes a network's route away.
func (i *Interface) DelRoute(p netip.Prefix) error {
	return run("route", "-q", "-n", "delete", family(p), p.String(), "-interface", i.name)
}

// Close: the utun going takes its routes with it.
func (i *Interface) Close() error { return nil }
