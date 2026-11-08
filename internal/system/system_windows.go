package system

import "net/netip"

// Interface is the client's interface on Windows: a Wintun adapter.
type Interface struct{ name string }

// Configure gives the adapter its own addresses.
func Configure(name string) (*Interface, error) {
	if err := run("netsh", "interface", "ipv4", "set", "address", "name="+name, "source=static", "address="+OwnIPv4.String(),
		"mask=255.255.255.255"); err != nil {
		return nil, err
	}
	_ = run("netsh", "interface", "ipv6", "add", "address", "interface="+name, "address="+OwnIPv6.String()+"/128", "store=active")
	return &Interface{name: name}, nil
}

func family(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "ipv4"
	}
	return "ipv6"
}

func nexthop(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "0.0.0.0"
	}
	return "::"
}

// AddRoute routes a network through the adapter, for as long as it is up.
func (i *Interface) AddRoute(p netip.Prefix) error {
	return run("netsh", "interface", family(p), "add", "route", "prefix="+p.String(), "interface="+i.name, "nexthop="+nexthop(p),
		"store=active")
}

// DelRoute takes a network's route away.
func (i *Interface) DelRoute(p netip.Prefix) error {
	return run("netsh", "interface", family(p), "delete", "route", "prefix="+p.String(), "interface="+i.name, "nexthop="+nexthop(p))
}

// Close: the adapter going takes its routes with it.
func (i *Interface) Close() error { return nil }
