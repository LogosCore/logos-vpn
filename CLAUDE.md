# CLAUDE.md

This is **logos-vpn**, Logos's VPN client (docs: logos-docs
`contracts/vpn-front.md`): a Go program an operator runs on their machine
to route it into a VPN tunnel's networks.

## Layout

- `cmd/logos-vpn`: the command: flags, privileges, the link's first dial,
  the interface and its routes (in step with core's `routes`), the stack,
  shutdown (bye, routes gone with the interface). `wintun_windows.go`
  (build tag `wintun`) embeds Wintun's DLL; the Makefile puts it there.
- `internal/client`: the client's half of the link: `client.go` the
  streams (TCP, a UDP association per local source, one ping stream),
  offsets, acks and windows mirroring core's legs
  (`logos-core/core/pkg/miniontunnels/vpn.go`); `link.go` the WebSocket:
  dial, hello and welcome, frames, reconnects within
  `protocol.VPNLinkGrace`, end and refusal.
- `internal/netstack`: gVisor's stack over the device: TCP ended there
  (the forwarder answers each SYN by the minion's result; a non-SYN packet
  of no connection is dropped, never reset), UDP and ICMP read off the
  device and written back as built packets (`packet.go`).
- `internal/system`: the interface's addresses and routes per OS (`ip`,
  `ifconfig`/`route`, `netsh`), and the plan of which routes go in.

## Build and test

```sh
make test    # go test -race ./...
make lint    # golangci-lint for linux, darwin and windows
make dist    # the six binaries in dist/
```

`GOTOOLCHAIN=local`: the module stays on Go 1.25.7 like core, gVisor and
x/ pinned to wireguard-go's versions (the newest gVisor needs Go 1.27).
The tests need no root: `internal/client/e2e_test.go` runs a second gVisor
stack as the machine against the client's stack over an in-memory device,
the test playing core.

During development against an unreleased protocol, `go.work` (git-ignored)
uses `../logos-golang-protocol`; drop it at release, after bumping the
protocol in `go.mod`.

The client shares the protocol with core and minions, nothing else of
core's.
