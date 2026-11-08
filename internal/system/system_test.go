package system

import (
	"net/netip"
	"strings"
	"testing"
)

func prefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// The machine's own networks, and core's address, stay out of the tunnel.
func TestPlan(t *testing.T) {
	own := []Network{{Prefix: netip.MustParsePrefix("192.168.1.0/24"), Interface: "wlan0"}}
	core := []netip.Addr{netip.MustParseAddr("10.0.5.20")}
	add, left := Plan(prefixes("10.0.0.0/24", "192.168.0.0/16", "10.0.5.0/24", "fd00:1::/64"), own, core)
	if len(add) != 2 || add[0].String() != "10.0.0.0/24" || add[1].String() != "fd00:1::/64" {
		t.Errorf("add %v", add)
	}
	if len(left) != 2 || !strings.Contains(left[0].Why, "through wlan0") || !strings.Contains(left[1].Why, "core's address") {
		t.Errorf("left %+v", left)
	}
}

func TestDiff(t *testing.T) {
	add, del := Diff(prefixes("10.0.0.0/24", "10.0.1.0/24"), prefixes("10.0.1.0/24", "10.0.2.0/24"))
	if len(add) != 1 || add[0].String() != "10.0.2.0/24" || len(del) != 1 || del[0].String() != "10.0.0.0/24" {
		t.Errorf("add %v del %v", add, del)
	}
}
