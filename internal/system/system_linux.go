package system

import "net/netip"

// Interface is the client's interface on Linux.
type Interface struct{ name string }

// Configure brings the interface up with its own addresses.
func Configure(name string) (*Interface, error) {
	if err := run("ip", "link", "set", "dev", name, "up"); err != nil {
		return nil, err
	}
	if err := run("ip", "-4", "addr", "add", OwnIPv4.String()+"/32", "dev", name); err != nil {
		return nil, err
	}
	// IPv6 may be off on the machine: its routes then fail alone.
	_ = run("ip", "-6", "addr", "add", OwnIPv6.String()+"/128", "dev", name, "nodad")
	return &Interface{name: name}, nil
}

func family(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "-4"
	}
	return "-6"
}

// AddRoute routes a network through the interface.
func (i *Interface) AddRoute(p netip.Prefix) error {
	return run("ip", family(p), "route", "replace", p.String(), "dev", i.name)
}

// DelRoute takes a network's route away.
func (i *Interface) DelRoute(p netip.Prefix) error {
	return run("ip", family(p), "route", "del", p.String(), "dev", i.name)
}

// Close takes what Configure did away; the interface going takes its
// routes with it.
func (i *Interface) Close() error { return nil }
